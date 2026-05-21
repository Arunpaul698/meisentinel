#!/bin/bash
# ── Meisentis — Google Cloud Run Deployment Script ──────────────────────────────
#
# This script builds the Meisentis unified container using Google Cloud Build
# and deploys it directly to Google Cloud Run as a serverless service.
#
# Prerequisites:
# 1. Google Cloud SDK installed (gcloud CLI)
# 2. Authenticated: gcloud auth login
# 3. Target project set: gcloud config set project YOUR_PROJECT_ID
# 4. Cloud Build and Cloud Run APIs enabled in your project.

set -e

# --- CONFIGURATION ---
DEFAULT_REGION="us-central1"
SERVICE_NAME="meisentis"

# Get current project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "")

if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" = "(unset)" ]; then
    echo "❌ Error: No Google Cloud Project ID is set. Please set it using:"
    echo "   gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "🚀 Deploying Meisentis to Google Cloud..."
echo "🔹 Project ID:  $PROJECT_ID"
echo "🔹 Service:     $SERVICE_NAME"
echo "🔹 Region:      $DEFAULT_REGION"
echo ""

# Step 1: Build the container using Google Cloud Build (no local Docker required!)
echo "📦 Step 1: Building container image via Google Cloud Build..."
gcloud builds submit --tag "gcr.io/$PROJECT_ID/$SERVICE_NAME"

# Step 2: Deploy to Google Cloud Run
echo ""
echo "☁️ Step 2: Deploying to Google Cloud Run (serverless)..."
gcloud run deploy "$SERVICE_NAME" \
    --image "gcr.io/$PROJECT_ID/$SERVICE_NAME" \
    --platform managed \
    --region "$DEFAULT_REGION" \
    --allow-unauthenticated \
    --port 8080

echo ""
echo "🎉 Successfully Deployed to Google Cloud Run!"
echo "--------------------------------------------------------"
echo "💡 IMPORTANT: Don't forget to set your secret environment variables"
echo "   (VIRUSTOTAL_API_KEY, ANTHROPIC_API_KEY, etc.) on Cloud Run."
echo "   You can set them in the GCP Console under Cloud Run -> Variables,"
echo "   or run the following command:"
echo ""
echo "   gcloud run services update $SERVICE_NAME \\"
echo "       --set-env-vars VIRUSTOTAL_API_KEY=\"your_key\",ANTHROPIC_API_KEY=\"your_key\" \\"
echo "       --region $DEFAULT_REGION"
echo "--------------------------------------------------------"
