import asyncio
import unittest
import os
import shutil
import tempfile
from rag import RagSystem


class TestRagSystem(unittest.TestCase):
    def setUp(self):
        # Setup clean temporary DB file
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_rag.db")
        self.rag = RagSystem(self.db_path)

    def tearDown(self):
        # Clean up database
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_database_initialization(self):
        """Verifies that the RAG SQLite tables initialize correctly."""
        self.assertTrue(os.path.exists(self.db_path))
        stats = self.rag.get_stats()
        self.assertEqual(stats["total_chunks"], 0)
        self.assertEqual(stats["total_documents"], 0)

    def test_text_chunking(self):
        """Verifies paragraph and overlapping chunking logic."""
        text = "Paragraph one is short.\n\nParagraph two is also short.\n\n" * 50
        chunks = self.rag.chunk_text(text, max_chars=500, overlap=100)
        self.assertTrue(len(chunks) > 1)
        for chunk in chunks:
            self.assertTrue(len(chunk) <= 500)

    def test_cosine_similarity(self):
        """Verifies vector cosine similarity values compute correctly."""
        v1 = [1.0, 0.0, 0.0]
        v2 = [1.0, 0.0, 0.0]
        v3 = [0.0, 1.0, 0.0]
        v4 = [0.5, 0.5, 0.0]

        # Exact match
        self.assertAlmostEqual(self.rag._cosine_similarity(v1, v2), 1.0, places=4)
        # Orthogonal
        self.assertAlmostEqual(self.rag._cosine_similarity(v1, v3), 0.0, places=4)
        # Partially similar
        self.assertAlmostEqual(self.rag._cosine_similarity(v1, v4), 0.7071, places=4)
        # Invalid vectors
        self.assertEqual(self.rag._cosine_similarity([], v1), 0.0)

    def test_dummy_ingestion_fallback(self):
        """Verifies ingestion saves chunks even when embedding API key is unconfigured."""
        title = "CVE-2023-38545 Playbook"
        content = "This is a detailed mock report containing mitigation recommendations for curl SOCKS5 heap overflow."
        
        # Ingest
        loop = asyncio.get_event_loop()
        chunks_added = loop.run_until_complete(self.rag.ingest_document(title, content))
        self.assertTrue(chunks_added > 0)

        # Check stats
        stats = self.rag.get_stats()
        self.assertEqual(stats["total_documents"], 1)
        self.assertEqual(stats["total_chunks"], chunks_added)


if __name__ == "__main__":
    unittest.main()
