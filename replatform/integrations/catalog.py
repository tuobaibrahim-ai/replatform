"""كتالوج التكاملات والمصادر المهنية — بيانات فقط، بلا مفاتيح أو أسرار.

كل موصل (Connector) قراءة فقط، ويستخدم HTTPS، ومضيفه مقيّد صراحةً.
المصادر (Resource) روابط مرجعية لمستودعات ومهارات وخدمات مجانية؛
الأسعار والحدود تتغير، لذا تحقّق من الرابط قبل الاعتماد عليها.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class Connector:
    id: str
    name: str
    category: str
    base_url: str
    docs: str
    description: str
    auth_env: str | None = None
    auth_header: str | None = None
    auth_prefix: str = ""
    keyless: bool = False
    read_only: bool = True
    sample_upload: bool = False
    max_response_mb: int = 8
    tags: tuple[str, ...] = ()

    @property
    def host(self) -> str:
        return (urlparse(self.base_url).hostname or "").lower()

    @property
    def requires_key(self) -> bool:
        return bool(self.auth_env) and not self.keyless


@dataclass(frozen=True)
class Resource:
    name: str
    category: str
    url: str
    description: str
    free_tier: str = ""
    notes: str = ""


CONNECTORS: tuple[Connector, ...] = (
    Connector(
        id="nvd",
        name="NVD CVE API 2.0",
        category="vulnerabilities",
        base_url="https://services.nvd.nist.gov",
        docs="https://nvd.nist.gov/developers/vulnerabilities",
        description="بحث في ثغرات CVE مع درجات CVSS والتواريخ والمراجع.",
        auth_env="NVD_API_KEY",
        auth_header="apiKey",
        keyless=True,
        tags=("cve", "cvss", "nist"),
    ),
    Connector(
        id="cisa_kev",
        name="CISA KEV",
        category="threat-intel",
        base_url="https://www.cisa.gov",
        docs="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        description="الثغرات المعروفة بالاستغلال الفعلي (Known Exploited Vulnerabilities).",
        keyless=True,
        max_response_mb=16,
        tags=("kev", "exploited", "cisa"),
    ),
    Connector(
        id="osv",
        name="OSV.dev",
        category="supply-chain",
        base_url="https://api.osv.dev",
        docs="https://google.github.io/osv-scanner/",
        description="ثغرات الحزم مفتوحة المصدر (npm, PyPI, Go, Maven, crates.io...).",
        keyless=True,
        tags=("dependencies", "sbom", "supply-chain"),
    ),
    Connector(
        id="github",
        name="GitHub REST",
        category="code",
        base_url="https://api.github.com",
        docs="https://docs.github.com/rest",
        description="بحث المستودعات العامة وبياناتها (نجوم، لغة، وصف، تحديث).",
        auth_env="GITHUB_TOKEN",
        auth_header="Authorization",
        auth_prefix="Bearer ",
        keyless=True,
        tags=("repositories", "code", "open-source"),
    ),
    Connector(
        id="huggingface",
        name="Hugging Face Hub",
        category="ai",
        base_url="https://huggingface.co",
        docs="https://huggingface.co/docs/hub/api",
        description="بحث النماذج ومجموعات البيانات المفتوحة في Hugging Face.",
        auth_env="HF_TOKEN",
        auth_header="Authorization",
        auth_prefix="Bearer ",
        keyless=True,
        tags=("models", "datasets", "ai"),
    ),
    Connector(
        id="virustotal",
        name="VirusTotal API v3",
        category="malware",
        base_url="https://www.virustotal.com",
        docs="https://docs.virustotal.com/reference/overview",
        description="سمعة الملفات والروابط والنطاقات وعناوين IP (يتطلب مفتاحاً).",
        auth_env="VIRUSTOTAL_API_KEY",
        auth_header="x-apikey",
        tags=("malware", "reputation", "ioc"),
    ),
    Connector(
        id="otx",
        name="AlienVault OTX",
        category="threat-intel",
        base_url="https://otx.alienvault.com",
        docs="https://otx.alienvault.com/api",
        description="استخبارات تهديدات مجتمعية لمؤشرات الاختراق (يتطلب مفتاحاً).",
        auth_env="OTX_API_KEY",
        auth_header="X-OTX-API-KEY",
        tags=("ioc", "pulses", "threat-intel"),
    ),
    Connector(
        id="malwarebazaar",
        name="MalwareBazaar",
        category="malware",
        base_url="https://mb-api.abuse.ch",
        docs="https://bazaar.abuse.ch/api/",
        description="بيانات عيّنات البرمجيات الخبيثة حسب التجزئة (يتطلب مفتاحاً).",
        auth_env="MALWAREBAZAAR_AUTH_KEY",
        auth_header="Auth-Key",
        tags=("malware", "samples", "hashes"),
    ),
    Connector(
        id="abuseipdb",
        name="AbuseIPDB",
        category="threat-intel",
        base_url="https://api.abuseipdb.com",
        docs="https://docs.abuseipdb.com/",
        description="سمعة عناوين IP وتقارير الإساءة (يتطلب مفتاحاً).",
        auth_env="ABUSEIPDB_API_KEY",
        auth_header="Key",
        tags=("ip", "reputation", "abuse"),
    ),
    Connector(
        id="shodan",
        name="Shodan",
        category="attack-surface",
        base_url="https://api.shodan.io",
        docs="https://developer.shodan.io/api",
        description="خدمات ومنافذ وعنوان IP مكشوفة على الإنترنت (يتطلب مفتاحاً).",
        auth_env="SHODAN_API_KEY",
        tags=("ports", "services", "exposure"),
    ),
    Connector(
        id="urlhaus",
        name="URLhaus API",
        category="malware",
        base_url="https://urlhaus-api.abuse.ch",
        docs="https://urlhaus-api.abuse.ch/",
        description=(
            "روابط توزيع البرمجيات الخبيثة، المضيفون، وتجزئات الحمولات "
            "(يتطلب مفتاح abuse.ch)."
        ),
        auth_env="ABUSECH_AUTH_KEY",
        auth_header="Auth-Key",
        tags=("malware", "url", "payload", "ioc"),
    ),
    Connector(
        id="threatfox",
        name="ThreatFox API",
        category="threat-intel",
        base_url="https://threatfox-api.abuse.ch",
        docs="https://threatfox-api.abuse.ch/",
        description=(
            "مؤشرات اختراق مجتمعية مع عائلة البرمجية الخبيثة ومستوى الثقة "
            "(يتطلب مفتاح abuse.ch)."
        ),
        auth_env="ABUSECH_AUTH_KEY",
        auth_header="Auth-Key",
        tags=("ioc", "c2", "malware", "threat-intel"),
    ),
)


RESOURCES: tuple[Resource, ...] = (
    # الذكاء الاصطناعي
    Resource("OpenRouter", "ai", "https://openrouter.ai/docs", "بوابة نماذج متعددة بواجهة OpenAI-compatible.", "نماذج مجانية محدودة", "تحقق من شروط الاستخدام وسياسة البيانات."),
    Resource("GroqCloud", "ai", "https://console.groq.com/docs", "استدلال سريع لواجهات OpenAI-compatible.", "طبقة مجانية بحدود معدل", "مناسب للوكلاء متعددي الخطوات."),
    Resource("Google AI Studio", "ai", "https://ai.google.dev/gemini-api/docs", "Gemini API ونماذج Gemma.", "طبقة مجانية محدودة", "قد تُستخدم البيانات للتحسين في الطبقة المجانية."),
    Resource("Mistral AI", "ai", "https://docs.mistral.ai/", "نماذج Mistral وCodestral.", "Experiment tier", "راجع سياسة التدريب والاستخدام التجاري."),
    Resource("Cloudflare Workers AI", "ai", "https://developers.cloudflare.com/workers-ai/", "استدلال على حافة الشبكة.", "Neurons يومية", "يتكامل مع Workers وD1."),
    Resource("Ollama", "ai", "https://ollama.com/", "تشغيل نماذج مفتوحة محلياً بلا شبكة.", "مجاني محلياً", "الأفضل للخصوصية والعيّنات الحساسة."),
    Resource("Hugging Face", "ai", "https://huggingface.co/docs", "نماذج ومجموعات بيانات ومكتبات.", "عام مجاني", "راجع ترخيص كل نموذج/مجموعة."),
    Resource("LangChain", "ai", "https://python.langchain.com/", "إطار بناء تطبيقات LLM ووكلاء.", "مفتوح المصدر", ""),
    Resource("LlamaIndex", "ai", "https://docs.llamaindex.ai/", "RAG وفهرسة بيانات للوكلاء.", "مفتوح المصدر", ""),
    Resource("Model Context Protocol", "ai", "https://modelcontextprotocol.io/", "معيار ربط الوكلاء بالأدوات والموارد.", "مفتوح", "راجع أمان الخوادم قبل الربط."),

    # البرمجة والمستودعات
    Resource("GitHub", "code", "https://docs.github.com/rest", "مستودعات وكود وإصدارات وقضايا.", "عام مجاني", "استخدم توكن لتجنب حدود المعدل."),
    Resource("GitLab", "code", "https://docs.gitlab.com/ee/api/", "مستودعات وCI/CD.", "طبقة مجانية", ""),
    Resource("Semgrep", "code", "https://semgrep.dev/docs/", "تحليل ثابت للكود وقواعد أمنية.", "مفتوح المصدر/سحابة مجانية", ""),
    Resource("Trivy", "code", "https://trivy.dev/", "فحص الحاويات والاعتماديات والأسرار.", "مفتوح المصدر", ""),
    Resource("Snyk", "code", "https://docs.snyk.io/", "فحص الاعتماديات والكود.", "طبقة مجانية", ""),
    Resource("OSV-Scanner", "code", "https://google.github.io/osv-scanner/", "فحص ثغرات الاعتماديات.", "مفتوح المصدر", ""),
    Resource("Stack Overflow", "code", "https://api.stackexchange.com/docs", "أسئلة وأجوبة برمجية.", "مجاني بحدود", ""),

    # الأمن السيبراني والهندسة العكسية
    Resource("MITRE ATT&CK", "security", "https://attack.mitre.org/resources/attack-data-and-tools/", "قاعدة تكتيكات وتقنيات المهاجمين.", "مجاني", "بيانات STIX كبيرة؛ نزّلها عند الحاجة."),
    Resource("OWASP Cheat Sheets", "security", "https://cheatsheetseries.owasp.org/", "إرشادات عملية لتأمين التطبيقات.", "مجاني", ""),
    Resource("PortSwigger Academy", "security", "https://portswigger.net/web-security", "تدريب عملي على أمن الويب.", "مجاني", ""),
    Resource("HackTricks", "security", "https://book.hacktricks.wiki/", "مرجع تقنيات اختبار الاختراق.", "مجاني", "للاستخدام المصرّح فقط."),
    Resource("YARA Rules", "security", "https://github.com/Yara-Rules/rules", "قواعد كشف برمجيات خبيثة.", "مفتوح المصدر", "اختبر القواعد قبل الإنتاج."),
    Resource("Sigma", "security", "https://github.com/SigmaHQ/sigma", "قواعد كشف موحدة للسجلات.", "مفتوح المصدر", ""),
    Resource("Ghidra", "security", "https://ghidra-sre.org/", "هندسة عكسية وتحليل ثنائي.", "مفتوح المصدر", ""),
    Resource("Rizin", "security", "https://rizin.re/", "إطار تفكيك وتحليل ثنائي.", "مفتوح المصدر", ""),
    Resource("Malpedia", "security", "https://malpedia.caad.fkie.fraunhofer.de/", "ملفات تعريف عائلات البرمجيات الخبيثة.", "بحثي", ""),
    Resource("MISP", "security", "https://www.misp-project.org/", "مشاركة استخبارات التهديدات.", "مفتوح المصدر", "يتطلب خادماً وثقة تشغيلية."),
    Resource("URLhaus", "security", "https://urlhaus.abuse.ch/api/", "روابط توزيع برمجيات خبيثة.", "مجاني بمفتاح", ""),
    Resource("ThreatFox", "security", "https://threatfox.abuse.ch/", "مؤشرات اختراق مجتمعية مرتبطة بعائلات البرمجيات الخبيثة.", "مجاني بمفتاح", ""),
    Resource("Feodo Tracker", "security", "https://feodotracker.abuse.ch/", "عناوين C2 لبعض العائلات.", "مجاني", ""),

    # استضافة وسيرفرات مجانية
    Resource("Cloudflare Workers", "hosting", "https://developers.cloudflare.com/workers/", "دوال حافة وواجهات API.", "100K طلب/يوم", "لا تحتاج بطاقة للبدء."),
    Resource("Cloudflare Pages", "hosting", "https://developers.cloudflare.com/pages/", "استضافة ثابتة.", "مجاني", ""),
    Resource("Render", "hosting", "https://render.com/docs", "خدمات ويب وقواعد بيانات.", "750 ساعة/شهر", "تتوقف الخدمة المجانية عند الخمول."),
    Resource("Koyeb", "hosting", "https://www.koyeb.com/docs", "خدمات Docker وواجهات API.", "نسخة مجانية واحدة", "تتوقف عند الخمول بعد ساعة."),
    Resource("Railway", "hosting", "https://docs.railway.com/", "نشر تطبيقات وقواعد بيانات.", "رصيد تجريبي/شهري", "راجع الحدود الحالية."),
    Resource("Vercel", "hosting", "https://vercel.com/docs", "استضافة واجهات ووظائف.", "Hobby مجاني", "للاستخدام غير التجاري غالباً."),
    Resource("Netlify", "hosting", "https://docs.netlify.com/", "استضافة ثابتة ووظائف.", "طبقة مجانية", ""),
    Resource("GitHub Pages", "hosting", "https://docs.github.com/pages", "استضافة ثابتة من المستودع.", "مجاني", ""),
    Resource("Oracle Cloud Free Tier", "hosting", "https://www.oracle.com/cloud/free/", "خادم دائم مجاني بمواصفات محدودة.", "Always Free", "يتطلب بطاقة للتحقق."),
    Resource("AWS Free Tier", "hosting", "https://aws.amazon.com/free/", "خدمات سحابية تجريبية/محدودة.", "12 شهراً/حدود دائمة", "راقب التكاليف بدقة."),

    # قواعد البيانات
    Resource("Supabase", "database", "https://supabase.com/docs", "Postgres + Auth + Storage + Realtime.", "مشروعان، 500MB", "تتوقف المشاريع الخاملة."),
    Resource("Neon", "database", "https://neon.com/docs", "Postgres serverless مع تفريعات.", "0.5GB/مشروع", "ممتاز لبيئات التطوير."),
    Resource("Turso", "database", "https://docs.turso.tech/", "SQLite/libSQL على الحافة.", "5GB و100 قاعدة", "مناسب للقراءة الكثيفة."),
    Resource("Cloudflare D1", "database", "https://developers.cloudflare.com/d1/", "SQLite داخل Workers.", "5GB إجمالاً", "مرتبط ببيئة Workers."),
    Resource("MongoDB Atlas", "database", "https://www.mongodb.com/docs/atlas/", "قاعدة مستندات مُدارة.", "M0 512MB", ""),
    Resource("Upstash Redis", "database", "https://upstash.com/docs/redis", "Redis عبر HTTP.", "500K أمر/شهر", "يدعم الوكلاء والخوادم اللامركزية."),
    Resource("Redis Cloud", "database", "https://redis.io/docs/latest/operate/rc/", "Redis مُدار.", "30MB", ""),
    Resource("Aiven", "database", "https://aiven.io/docs", "Postgres/Redis/Kafka مُدارة.", "خطط تجريبية", ""),
    Resource("CockroachDB Serverless", "database", "https://www.cockroachlabs.com/docs/", "SQL موزّع.", "طبقة مجانية", ""),
    Resource("PocketBase", "database", "https://pocketbase.io/docs/", "خلفية SQLite مفتوحة المصدر.", "مجاني/ذاتي", "مناسب للنماذج الأولية."),
)


def get_connector(connector_id: str) -> Connector:
    wanted = str(connector_id or "").strip().lower()
    for connector in CONNECTORS:
        if connector.id == wanted:
            return connector
    raise KeyError(f"موصل غير معروف: {connector_id}")


def list_connectors(category: str | None = None) -> list[Connector]:
    if not category:
        return list(CONNECTORS)
    wanted = category.strip().lower()
    return [connector for connector in CONNECTORS if connector.category == wanted]


def list_resources(category: str | None = None) -> list[Resource]:
    if not category:
        return list(RESOURCES)
    wanted = category.strip().lower()
    return [resource for resource in RESOURCES if resource.category == wanted]
