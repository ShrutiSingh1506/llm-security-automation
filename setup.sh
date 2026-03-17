#!/bin/bash

echo "🚀 LLM Security Automation - Quick Setup"
echo "========================================"
echo ""

# Check Python version
echo "1️⃣  Checking Python version..."
python3 --version

# Create virtual environment
echo ""
echo "2️⃣  Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo ""
echo "3️⃣  Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo ""
echo "4️⃣  Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create .env file
echo ""
echo "5️⃣  Setting up environment..."
if [ ! -f .env ]; then
    cp .env.template .env
    echo "✓ Created .env file"
    echo ""
    echo "⚠️  IMPORTANT: Edit .env and add your OpenAI API key!"
    echo "   Get your key from: https://platform.openai.com/api-keys"
else
    echo "✓ .env file already exists"
fi

# Create output directory
mkdir -p output

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env and add your OPENAI_API_KEY"
echo "2. Run: python llm_security_automation.py"
echo ""
echo "Cost: ~$2-5 for entire project using gpt-4o-mini"
