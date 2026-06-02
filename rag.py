import os
import sqlite3
import json
import math
import logging
import httpx
import re
from typing import Optional

# Setup logger
logger = logging.getLogger("meisentis.rag")
logger.setLevel(logging.INFO)

# Environment Keys
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")


class RagSystem:
    def __init__(self, db_path: str = "meisentis_rag.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the SQLite database schema if it does not exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rag_chunks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    content TEXT,
                    metadata TEXT,
                    embedding TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    async def get_embedding(self, text: str) -> list[float]:
        """Fetch embedding vector from OpenAI or Gemini API based on configured keys."""
        # Clean text
        text = text.replace("\n", " ").strip()
        if not text:
            return []

        # 1. Try OpenAI if configured
        if OPENAI_API_KEY:
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(
                        "https://api.openai.com/v1/embeddings",
                        headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                        json={"input": text, "model": "text-embedding-3-small"}
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    return data["data"][0]["embedding"]
            except Exception as e:
                logger.error(f"OpenAI embedding call failed: {e}")

        # 2. Try Gemini if configured
        if GEMINI_API_KEY:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent?key={GEMINI_API_KEY}"
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(
                        url,
                        json={"content": {"parts": [{"text": text}]}}
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    return data["embedding"]["values"]
            except Exception as e:
                logger.error(f"Gemini embedding call failed: {e}")

        # 3. Fallback: print warning and return a dummy deterministic representation
        logger.warning("No embedding API keys configured (GEMINI_API_KEY or OPENAI_API_KEY). RAG queries will return empty.")
        return []

    def chunk_text(self, text: str, max_chars: int = 1200, overlap: int = 200) -> list[str]:
        """Split document text into overlapping chunks using paragraph & sentence boundaries."""
        paragraphs = text.split("\n\n")
        chunks = []
        current_chunk = ""

        for p in paragraphs:
            p = p.strip()
            if not p:
                continue
            
            # If paragraph itself is huge, chunk by sentences
            if len(p) > max_chars:
                sentences = re.split(r'(?<=[.!?]) +', p)
                for s in sentences:
                    if len(current_chunk) + len(s) + 1 > max_chars:
                        if current_chunk:
                            chunks.append(current_chunk.strip())
                        # Retain overlap from end of current chunk
                        current_chunk = current_chunk[-overlap:] if len(current_chunk) > overlap else ""
                    current_chunk += s + " "
            else:
                if len(current_chunk) + len(p) + 2 > max_chars:
                    if current_chunk:
                        chunks.append(current_chunk.strip())
                    current_chunk = current_chunk[-overlap:] if len(current_chunk) > overlap else ""
                current_chunk += p + "\n\n"

        if current_chunk.strip():
            chunks.append(current_chunk.strip())

        return chunks

    async def ingest_document(self, title: str, content: str, metadata: dict = None) -> int:
        """Chunks a document, computes embeddings, and stores them in SQLite."""
        chunks = self.chunk_text(content)
        metadata_str = json.dumps(metadata or {})
        chunks_added = 0

        for chunk in chunks:
            embedding = await self.get_embedding(chunk)
            if not embedding:
                # If embedding fails, save chunk with empty embedding to allow keyword-fallback
                embedding_str = "[]"
            else:
                embedding_str = json.dumps(embedding)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO rag_chunks (title, content, metadata, embedding) VALUES (?, ?, ?, ?)",
                    (title, chunk, metadata_str, embedding_str)
                )
                conn.commit()
            chunks_added += 1

        logger.info(f"Ingested document '{title}' into {chunks_added} chunks.")
        return chunks_added

    def _cosine_similarity(self, v1: list[float], v2: list[float]) -> float:
        """Compute the cosine similarity of two vectors."""
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        dot_product = sum(x * y for x, y in zip(v1, v2))
        mag1 = math.sqrt(sum(x * x for x in v1))
        mag2 = math.sqrt(sum(x * x for x in v2))
        if mag1 == 0.0 or mag2 == 0.0:
            return 0.0
        return dot_product / (mag1 * mag2)

    async def retrieve(self, query: str, limit: int = 3) -> list[dict]:
        """Query RAG for contextually similar incident reports."""
        query_vector = await self.get_embedding(query)
        if not query_vector:
            return []

        results = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, content, metadata, embedding FROM rag_chunks")
            rows = cursor.fetchall()

            for row in rows:
                try:
                    stored_vector = json.loads(row["embedding"])
                except Exception:
                    continue
                
                if not stored_vector:
                    continue

                similarity = self._cosine_similarity(query_vector, stored_vector)
                
                # Minimum score threshold
                if similarity >= 0.50:
                    results.append({
                        "id": row["id"],
                        "title": row["title"],
                        "content": row["content"],
                        "metadata": json.loads(row["metadata"]),
                        "score": round(similarity, 4)
                    })

        # Sort by similarity score descending
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:limit]

    def get_stats(self) -> dict:
        """Returns storage metrics of the RAG system."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*), COUNT(DISTINCT title) FROM rag_chunks")
            total_chunks, total_docs = cursor.fetchone()
            return {
                "total_chunks": total_chunks or 0,
                "total_documents": total_docs or 0
            }
