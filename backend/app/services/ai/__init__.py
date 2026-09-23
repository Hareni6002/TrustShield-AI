from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

from app.services.ai.service import answer_question, generate_summary

__all__ = ["answer_question", "generate_summary"]
