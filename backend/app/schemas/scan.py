from datetime import datetime

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class URLAnalysis(BaseModel):
    full_url: str
    scheme: str
    hostname: str
    registered_domain: str | None = None
    subdomain: str | None = None
    suffix: str | None = None
    path: str
    query: str | None = None
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    dot_count: int
    hyphen_count: int
    underscore_count: int
    digit_count: int
    special_character_count: int
    subdomain_count: int
    has_https: bool
    has_ip_address: bool
    has_at_symbol: bool
    has_double_slash_path: bool
    has_punycode: bool
    suspicious_keyword_count: int
    suspicious_keywords: list[str]
    is_shortened_url: bool


class DomainAnalysis(BaseModel):
    domain_name: str
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    name_servers: list[str] = []
    domain_age_days: int | None = None
    registration_remaining_days: int | None = None
    lookup_status: str


class SSLAnalysis(BaseModel):
    ssl_available: bool
    ssl_valid: bool
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    days_until_expiry: int | None = None
    error: str | None = None


class DNSAnalysis(BaseModel):
    dns_resolves: bool
    ip_addresses: list[str]
    ipv6_addresses: list[str]
    mx_records: list[str]
    name_servers: list[str]


class HTTPAnalysis(BaseModel):
    http_status: int | None = None
    final_url: str | None = None
    redirect_count: int
    redirect_chain: list[str]
    page_title: str | None = None
    meta_description: str | None = None
    has_password_field: bool = False
    has_login_form: bool = False
    has_payment_keywords: bool = False
    external_links: int = 0
    internal_links: int = 0
    error: str | None = None


class BrandAnalysis(BaseModel):
    detected_brand: str | None = None
    brand_similarity_score: int
    possible_brand_impersonation: bool
    possible_typosquatting: bool
    possible_homoglyph_impersonation: bool
    misleading_subdomain_detected: bool
    brand_like_subdomain: str | None = None
    legitimate_domains: list[str]
    unicode_domain: str | None = None
    explanation: str | None = None


class LexicalAnalysis(BaseModel):
    tld: str
    tld_risk_indicator: str
    domain_entropy: float
    domain_randomness_score: int
    domain_digit_count: int
    domain_digit_ratio: float
    domain_hyphen_count: int
    repeated_hyphens: bool
    consecutive_digits: bool
    mixed_alpha_numeric_tokens: bool
    suspicious_path_keywords: list[str]
    lexical_risk_score: int
    lexical_risk_level: str


class ScanResponse(BaseModel):
    url: str
    normalized_url: str
    technical_trust_score: int
    technical_risk_score: int
    risk_level: str
    url_analysis: URLAnalysis
    domain_analysis: DomainAnalysis
    ssl_analysis: SSLAnalysis
    dns_analysis: DNSAnalysis
    http_analysis: HTTPAnalysis
    content_analysis: HTTPAnalysis
    brand_analysis: BrandAnalysis
    lexical_analysis: LexicalAnalysis
    positive_signals: list[str]
    warning_signals: list[str]
