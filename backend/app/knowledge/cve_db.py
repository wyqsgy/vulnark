from dataclasses import dataclass, asdict
from typing import List, Dict, Optional


@dataclass
class CVERecord:
    cve_id: str
    name: str
    description: str
    severity: str
    cvss_score: float
    affected_component: str
    affected_versions: str
    fixed_version: str
    poc_available: bool
    references: List[str]
    tags: List[str]


class CVEDatabase:
    def __init__(self):
        self._records: Dict[str, CVERecord] = {}
        self._load_builtin()

    def _load_builtin(self):
        entries = [
            CVERecord("CVE-2022-22965", "Spring4Shell RCE",
                       "Spring Framework通过数据绑定特性实现RCE，影响JDK9+",
                       "critical", 9.8, "Spring Framework", "5.3.0 - 5.3.17, 5.2.0 - 5.2.19",
                       "5.3.18 / 5.2.20", True,
                       ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
                       ["rce", "spring", "java"]),
            CVERecord("CVE-2022-22963", "Spring Cloud Function SpEL RCE",
                       "Spring Cloud Function路由表达式注入导致RCE",
                       "critical", 9.8, "Spring Cloud Function", "3.1.0 - 3.2.2", "3.2.3",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2022-22963"],
                       ["rce", "spring", "spel"]),
            CVERecord("CVE-2022-22947", "Spring Cloud Gateway SpEL RCE",
                       "Spring Cloud Gateway Actuator端点SpEL注入RCE",
                       "critical", 10.0, "Spring Cloud Gateway", "3.1.0, 3.0.0 - 3.0.6",
                       "3.1.1 / 3.0.7",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2022-22947"],
                       ["rce", "spring", "gateway"]),
            CVERecord("CVE-2016-4437", "Shiro RememberMe 反序列化",
                       "Apache Shiro RememberMe使用硬编码密钥，可构造反序列化攻击",
                       "critical", 9.8, "Apache Shiro", "< 1.4.2", "1.4.2",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2016-4437"],
                       ["deserialization", "shiro", "rce"]),
            CVERecord("CVE-2020-1957", "Shiro 权限绕过",
                       "Spring Boot与Shiro配合使用时的认证绕过漏洞",
                       "high", 7.5, "Apache Shiro", "< 1.5.2", "1.5.2",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2020-1957"],
                       ["auth_bypass", "shiro"]),
            CVERecord("CVE-2021-44228", "Log4Shell",
                       "Apache Log4j2 JNDI注入远程代码执行，影响面极广",
                       "critical", 10.0, "Apache Log4j2", "2.0 - 2.14.1", "2.15.0",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                       ["rce", "log4j", "jndi"]),
            CVERecord("CVE-2017-18349", "Fastjson 反序列化RCE",
                       "Fastjson通过@type指定恶意类实现RCE",
                       "critical", 9.8, "Fastjson", "< 1.2.45", "1.2.83",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2017-18349"],
                       ["rce", "fastjson", "deserialization"]),
            CVERecord("CVE-2021-29441", "Nacos 认证绕过",
                       "Nacos默认配置下可绕过认证访问管理接口",
                       "high", 7.5, "Nacos", "< 1.4.1", "1.4.1",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2021-29441"],
                       ["auth_bypass", "nacos"]),
            CVERecord("CVE-2021-29442", "Nacos Derby SQL注入RCE",
                       "Nacos内嵌Derby数据库存在SQL注入可导致RCE",
                       "critical", 9.8, "Nacos", "< 2.0.3", "2.0.3",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2021-29442"],
                       ["rce", "nacos", "sqli"]),
            CVERecord("CVE-2018-20062", "ThinkPHP RCE",
                       "ThinkPHP 5.x框架RCE漏洞",
                       "critical", 9.8, "ThinkPHP", "5.0.x < 5.0.24, 5.1.x",
                       "5.0.24 / 5.1.31",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2018-20062"],
                       ["rce", "thinkphp"]),
            CVERecord("CVE-2020-14882", "WebLogic 未授权RCE",
                       "WebLogic Console未授权访问导致RCE",
                       "critical", 9.8, "Oracle WebLogic", "10.3.6.0, 12.1.3, 12.2.1.3, 12.2.1.4, 14.1.1",
                       "CPU October 2020",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2020-14882"],
                       ["rce", "weblogic"]),
            CVERecord("CVE-2017-10271", "WebLogic XMLDecoder 反序列化",
                       "WebLogic WLS-WSAT组件XMLDecoder反序列化RCE",
                       "critical", 9.8, "Oracle WebLogic", "10.3.6.0, 12.1.3, 12.2.1.2, 12.2.1.3",
                       "CPU October 2017",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2017-10271"],
                       ["rce", "weblogic", "deserialization"]),
            CVERecord("CVE-2022-26134", "Confluence OGNL RCE",
                       "Confluence Server/Data Center OGNL注入RCE",
                       "critical", 9.8, "Atlassian Confluence", "所有版本", "7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"],
                       ["rce", "confluence", "ognl"]),
            CVERecord("CVE-2022-1388", "F5 BIG-IP iControl REST RCE",
                       "F5 BIG-IP iControl REST认证绕过RCE",
                       "critical", 9.8, "F5 BIG-IP", "16.1.x < 16.1.2.2, 15.1.x < 15.1.5.1, 14.1.x < 14.1.4.6, 13.1.x < 13.1.5",
                       "各分支修复版本",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"],
                       ["rce", "f5"]),
            CVERecord("CVE-2022-43385", "XXL-JOB 执行器未授权RCE",
                       "XXL-JOB执行器API未授权访问导致命令执行",
                       "critical", 9.8, "XXL-JOB", "< 2.4.0", "2.4.0",
                       True, ["https://github.com/xuxueli/xxl-job/issues/3100"],
                       ["rce", "xxljob"]),
            CVERecord("CVE-2020-17518", "Apache Flink 任意Jar上传RCE",
                       "Flink Dashboard任意文件上传漏洞",
                       "critical", 7.5, "Apache Flink", "< 1.11.3", "1.11.3",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2020-17518"],
                       ["rce", "flink", "upload"]),
            CVERecord("CVE-2018-1000861", "Jenkins RCE",
                       "Jenkins多个漏洞组合实现RCE",
                       "critical", 9.8, "Jenkins", "< 2.138.2", "2.138.2 / 2.150.1",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2018-1000861"],
                       ["rce", "jenkins"]),
            CVERecord("CVE-2022-22978", "Spring Security 正则绕过",
                       "Spring Security授权绕过漏洞",
                       "critical", 9.8, "Spring Security", "5.5.x < 5.5.7, 5.6.x < 5.6.4",
                       "5.5.7 / 5.6.4",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2022-22978"],
                       ["auth_bypass", "spring", "security"]),
            CVERecord("CVE-2023-46604", "Apache ActiveMQ 反序列化RCE",
                       "ActiveMQ OpenWire协议MarshallAWT反序列化RCE",
                       "critical", 10.0, "Apache ActiveMQ", "<= 5.18.2, 5.17.x < 5.17.5, 5.16.x < 5.16.7",
                       "5.18.3 / 5.17.6 / 5.16.8",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"],
                       ["rce", "activemq", "deserialization"]),
            CVERecord("CVE-2023-28708", "Tomcat Cookie 处理信息泄露",
                       "Tomcat会话ID通过Set-Cookie头泄露到非安全通道",
                       "high", 7.5, "Apache Tomcat", "11.0.0-M1 - 11.0.0-M4, 10.1.0-M1 - 10.1.5, 9.0.0-M1 - 9.0.71, 8.5.0 - 8.5.85",
                       "11.0.0-M5 / 10.1.6 / 9.0.72 / 8.5.86",
                       False, ["https://nvd.nist.gov/vuln/detail/CVE-2023-28708"],
                       ["info_disclosure", "tomcat"]),
            CVERecord("CVE-2023-20861", "Spring Expression SpEL DoS",
                       "Spring Framework SpEL表达式求值导致拒绝服务",
                       "medium", 5.9, "Spring Framework", "6.0.0 - 6.0.6, 5.3.0 - 5.3.25, 5.2.0 - 5.2.22",
                       "6.0.7 / 5.3.26 / 5.2.23",
                       False, ["https://nvd.nist.gov/vuln/detail/CVE-2023-20861"],
                       ["dos", "spring", "spel"]),
            CVERecord("CVE-2024-50379", "Apache Tomcat TOCTOU RCE",
                       "Tomcat大小写不敏感文件系统上JSP编译竞态条件RCE",
                       "critical", 9.8, "Apache Tomcat", "11.0.0-M1 - 11.0.1, 10.1.0-M1 - 10.1.33, 9.0.0.M1 - 9.0.97",
                       "11.0.2 / 10.1.34 / 9.0.98",
                       True, ["https://nvd.nist.gov/vuln/detail/CVE-2024-50379"],
                       ["rce", "tomcat", "race_condition"]),
        ]

        for entry in entries:
            self._records[entry.cve_id] = entry

    def get_by_cve_id(self, cve_id: str) -> Optional[CVERecord]:
        return self._records.get(cve_id)

    def get_by_component(self, component: str) -> List[CVERecord]:
        return [r for r in self._records.values()
                if component.lower() in r.affected_component.lower()]

    def get_by_severity(self, severity: str) -> List[CVERecord]:
        return [r for r in self._records.values() if r.severity == severity]

    def get_by_tag(self, tag: str) -> List[CVERecord]:
        return [r for r in self._records.values() if tag in r.tags]

    def search(self, keyword: str) -> List[CVERecord]:
        kw = keyword.lower()
        return [r for r in self._records.values()
                if kw in r.cve_id.lower() or kw in r.name.lower()
                or kw in r.description.lower() or kw in r.affected_component.lower()]

    def list_all(self) -> List[CVERecord]:
        return list(self._records.values())

    def enrich_vulnerability(self, vuln_data: dict) -> dict:
        cve_ids = vuln_data.get("cve_ids", "")
        if isinstance(cve_ids, str):
            cve_list = [c.strip() for c in cve_ids.split(",") if c.strip()]
        elif isinstance(cve_ids, list):
            cve_list = cve_ids
        else:
            cve_list = []

        enriched_cves = []
        for cid in cve_list:
            record = self.get_by_cve_id(cid)
            if record:
                enriched_cves.append(asdict(record))

        vuln_data["cve_details"] = enriched_cves
        return vuln_data

    @property
    def total(self) -> int:
        return len(self._records)


cve_db = CVEDatabase()
