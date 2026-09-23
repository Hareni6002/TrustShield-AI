from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

from app.services.reputation.aggregator import analyze_reputation

__all__ = ["analyze_reputation"]
