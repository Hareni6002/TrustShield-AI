from pydantic import BaseModel, Field, field_validator


REPORT_CATEGORIES = {"phishing", "fake_shopping", "fake_job", "investment_scam", "loan_scam", "crypto_scam", "brand_impersonation", "credential_theft", "malware", "other"}
REPORT_STATUSES = {"pending", "verified", "rejected"}


class CommunityReportCreate(BaseModel):
    url: str = Field(min_length=4, max_length=4096)
    category: str = Field(min_length=2, max_length=80)
    description: str = Field(min_length=10, max_length=5000)
    reporter_name: str | None = Field(default=None, max_length=120)
    reporter_email: str | None = Field(default=None, max_length=320)

    @field_validator("category")
    @classmethod
    def valid_category(cls, value: str) -> str:
        value = value.strip().lower().replace(" ", "_")
        if value not in REPORT_CATEGORIES:
            raise ValueError("Unsupported report category.")
        return value

    @field_validator("reporter_email")
    @classmethod
    def valid_email(cls, value: str | None) -> str | None:
        if value and ("@" not in value or "." not in value.rsplit("@", 1)[-1]):
            raise ValueError("Enter a valid reporter email.")
        return value


class ReportModeration(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def valid_status(cls, value: str) -> str:
        if value not in REPORT_STATUSES - {"pending"}:
            raise ValueError("Moderation status must be verified or rejected.")
        return value
