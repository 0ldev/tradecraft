"""Tool registry: the single source of truth for which tools exist, and
the translation from `ToolSpec` to an OpenAI-style function-calling
definition (the shape litellm expects regardless of which backend is
actually behind LLM_BASE_URL).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from tradecraft.tools.actuator_probe import ActuatorProbe
from tradecraft.tools.acl_bypass_probe import AclBypassProbe
from tradecraft.tools.ai_stack_probe import AiStackProbe
from tradecraft.tools.amass import Amass
from tradecraft.tools.anon_service_probe import AnonServiceProbe
from tradecraft.tools.api_version_shadow_probe import ApiVersionShadowProbe
from tradecraft.tools.arjun import Arjun
from tradecraft.tools.artifact_repo_exposure_probe import ArtifactRepoExposureProbe
from tradecraft.tools.asn_discovery import AsnDiscovery
from tradecraft.tools.auth_bootstrap import AuthBootstrap
from tradecraft.tools.azure_tenant_recon import AzureTenantRecon
from tradecraft.tools.bloodhound import Bloodhound
from tradecraft.tools.bucket_permission_exploit import BucketPermissionExploit
from tradecraft.tools.bucket_permission_probe import BucketPermissionProbe
from tradecraft.tools.base import Tool
from tradecraft.tools.cache_deception_probe import CacheDeceptionProbe
from tradecraft.tools.cache_poison_probe import CachePoisonProbe
from tradecraft.tools.cero import Cero
from tradecraft.tools.cewl import Cewl
from tradecraft.tools.cicd_exposure_probe import CicdExposureProbe
from tradecraft.tools.clairvoyance import Clairvoyance
from tradecraft.tools.certipy_enum import CertipyEnum
from tradecraft.tools.certipy_exploit import CertipyExploit
from tradecraft.tools.coercer import Coercer
from tradecraft.tools.cloud_identity_pool_probe import CloudIdentityPoolProbe
from tradecraft.tools.cloud_metadata_credential_probe import CloudMetadataCredentialProbe
from tradecraft.tools.cloudenum import Cloudenum
from tradecraft.tools.cloudfail import Cloudfail
from tradecraft.tools.cloudfox import Cloudfox
from tradecraft.tools.cmseek import CMSeeK
from tradecraft.tools.commix import Commix
from tradecraft.tools.corsy import Corsy
from tradecraft.tools.crlf_injection_probe import CrlfInjectionProbe
from tradecraft.tools.craftcms_transform_rce_probe import CraftcmsTransformRceProbe
from tradecraft.tools.csrf_probe import CsrfProbe
from tradecraft.tools.cupp import Cupp
from tradecraft.tools.cve_intel_enricher import CveIntelEnricher
from tradecraft.tools.cyberpanel_rce_probe import CyberPanelRceProbe
from tradecraft.tools.dalfox import Dalfox
from tradecraft.tools.dangling_resource_probe import DanglingResourceProbe
from tradecraft.tools.dependency_confusion_probe import DependencyConfusionProbe
from tradecraft.tools.deserialization_probe import DeserializationProbe
from tradecraft.tools.deserialization_probe_dotnet import DeserializationProbeDotnet
from tradecraft.tools.dns_axfr import DnsAxfr
from tradecraft.tools.dnsx import Dnsx
from tradecraft.tools.docker_api_probe import DockerApiProbe
from tradecraft.tools.dork_search_probe import DorkSearchProbe
from tradecraft.tools.drupal_jsonapi_sqli_probe import DrupalJsonapiSqliProbe
from tradecraft.tools.email_auth_posture import EmailAuthPosture
from tradecraft.tools.email_header_injection_probe import EmailHeaderInjectionProbe
from tradecraft.tools.fastcgi_exploit import FastcgiExploit
from tradecraft.tools.favicon_correlator import FaviconCorrelator
from tradecraft.tools.ffuf import Ffuf
from tradecraft.tools.firebase_probe import FirebaseProbe
from tradecraft.tools.flowise_token_leak_probe import FlowiseTokenLeakProbe
from tradecraft.tools.ffuf_vhost import FfufVhost
from tradecraft.tools.form_fuzzer import FormFuzzer
from tradecraft.tools.gau import Gau
from tradecraft.tools.ghauri import Ghauri
from tradecraft.tools.gitdorker import GitDorker
from tradecraft.tools.gitdumper import GitDumper
from tradecraft.tools.gowitness import Gowitness
from tradecraft.tools.graphql_authz_probe import GraphqlAuthzProbe
from tradecraft.tools.graphql_introspect import GraphqlIntrospect
from tradecraft.tools.host_header_injection_probe import HostHeaderInjectionProbe
from tradecraft.tools.hpp_probe import HppProbe
from tradecraft.tools.http_request import HttpRequest
from tradecraft.tools.http_write_request import HttpWriteRequest
from tradecraft.tools.http_smuggling_probe import HttpSmugglingProbe
from tradecraft.tools.httpx_probe import HttpxProbe
from tradecraft.tools.hydra import Hydra
from tradecraft.tools.identity_auth_bypass import IdentityAuthBypass
from tradecraft.tools.idor_probe import IdorProbe
from tradecraft.tools.ilias_rce_probe import IliasRceProbe
from tradecraft.tools.interactsh import Interactsh
from tradecraft.tools.jenkins_unauth_probe import JenkinsUnauthProbe
from tradecraft.tools.jupyter_exposure_probe import JupyterExposureProbe
from tradecraft.tools.jwt_algorithm_confusion_probe import JwtAlgorithmConfusionProbe
from tradecraft.tools.jwt_analyze import JwtAnalyze
from tradecraft.tools.jwt_crack import JwtCrack
from tradecraft.tools.jwt_tool import JwtTool
from tradecraft.tools.k8s_sa_token_theft import K8sSaTokenTheft
from tradecraft.tools.katana import Katana
from tradecraft.tools.kerberoast import Kerberoast
from tradecraft.tools.kerbrute import Kerbrute
from tradecraft.tools.kerbrute_spray import KerbruteSpray
from tradecraft.tools.kernel_privesc_exploit import KernelPrivescExploit
from tradecraft.tools.kiterunner import Kiterunner
from tradecraft.tools.kube_hunter_enum import KubeHunterEnum
from tradecraft.tools.kube_hunter_exploit import KubeHunterExploit
from tradecraft.tools.kubectl import Kubectl
from tradecraft.tools.kubectl_exploit import KubectlExploit
from tradecraft.tools.laravel_exploit import LaravelExploit
from tradecraft.tools.linkfinder import LinkFinder
from tradecraft.tools.linpeas import Linpeas
from tradecraft.tools.local_credential_harvest import LocalCredentialHarvest
from tradecraft.tools.mail_access_probe import MailAccessProbe
from tradecraft.tools.magento_cosmicsting_probe import MagentoCosmicStingProbe
from tradecraft.tools.mass_assignment_probe import MassAssignmentProbe
from tradecraft.tools.netexec_enum import NetexecEnum
from tradecraft.tools.netexec_exploit import NetexecExploit
from tradecraft.tools.nmap_scan import NmapScan
from tradecraft.tools.nmap_vuln_scan import NmapVulnScan
from tradecraft.tools.nosql_injection_probe import NosqlInjectionProbe
from tradecraft.tools.ntlm_info_disclosure_probe import NtlmInfoDisclosureProbe
from tradecraft.tools.nuclei import Nuclei
from tradecraft.tools.oauth_redirect_probe import OauthRedirectProbe
from tradecraft.tools.openapi_spec_discovery_probe import OpenApiSpecDiscoveryProbe
from tradecraft.tools.openapi_fuzz import OpenApiFuzz
from tradecraft.tools.open_redirect_probe import OpenRedirectProbe
from tradecraft.tools.openvpn_probe import OpenvpnProbe
from tradecraft.tools.pacu_enum import PacuEnum
from tradecraft.tools.pacu_exploit import PacuExploit
from tradecraft.tools.path_traversal_probe import PathTraversalProbe
from tradecraft.tools.perimeter_gateway_probe import PerimeterGatewayProbe
from tradecraft.tools.php_lfi import PhpLfi
from tradecraft.tools.php_cgi_arg_injection_probe import PhpCgiArgInjectionProbe
from tradecraft.tools.phpggc import Phpggc
from tradecraft.tools.playwright_engine import PlaywrightEngine
from tradecraft.tools.powerview import PowerView
from tradecraft.tools.price_manipulation_probe import PriceManipulationProbe
from tradecraft.tools.pod_exec_enum import PodExecEnum
from tradecraft.tools.prototype_pollution_probe import PrototypePollutionProbe
from tradecraft.tools.race_condition_probe import RaceConditionProbe
from tradecraft.tools.redis_rce_exploit import RedisRceExploit
from tradecraft.tools.registry_tag_enum import RegistryTagEnum
from tradecraft.tools.response_security_audit import ResponseSecurityAudit
from tradecraft.tools.retire_js import RetireJs
from tradecraft.tools.saml_signature_bypass_probe import SamlSignatureBypassProbe
from tradecraft.tools.scoutsuite_audit import ScoutsuiteAudit
from tradecraft.tools.searchsploit import Searchsploit
from tradecraft.tools.secretsdump import Secretsdump
from tradecraft.tools.sensitive_file_probe import SensitiveFileProbe
from tradecraft.tools.serverless_exposure_probe import ServerlessExposureProbe
from tradecraft.tools.shodan_internetdb import ShodanInternetdb
from tradecraft.tools.smuggler import Smuggler
from tradecraft.tools.smtp_probe import SmtpProbe
from tradecraft.tools.spa_crawl import SpaCrawl
from tradecraft.tools.sqlmap import Sqlmap
from tradecraft.tools.ssh_key_reuse_probe import SshKeyReuseProbe
from tradecraft.tools.ssrf_probe import SsrfProbe
from tradecraft.tools.sqli_login import SqliLogin
from tradecraft.tools.subdomain_permute import SubdomainPermute
from tradecraft.tools.subfinder import Subfinder
from tradecraft.tools.subjs import Subjs
from tradecraft.tools.subzy import Subzy
from tradecraft.tools.tcp_probe import TcpProbe
from tradecraft.tools.teamcity_auth_bypass_probe import TeamCityAuthBypassProbe
from tradecraft.tools.testssl import TestSsl
from tradecraft.tools.ticketer import Ticketer
from tradecraft.tools.tplmap import Tplmap
from tradecraft.tools.trivy_k8s_scan import TrivyK8sScan
from tradecraft.tools.trivy_scan import TrivyScan
from tradecraft.tools.trufflehog import TruffleHog
from tradecraft.tools.unauth_datastore_probe import UnauthDatastoreProbe
from tradecraft.tools.unix_privesc_exploit import UnixPrivescExploit
from tradecraft.tools.wafw00f import Wafw00f
from tradecraft.tools.websocket_security_probe import WebsocketSecurityProbe
from tradecraft.tools.xxe_probe import XxeProbe
from tradecraft.tools.webanalyze import Webanalyze
from tradecraft.tools.webshell_upload import WebshellUpload
from tradecraft.tools.whatweb import WhatWeb
from tradecraft.tools.winpeas import Winpeas
from tradecraft.tools.workflow_step_bypass_probe import WorkflowStepBypassProbe
from tradecraft.tools.wpscan import WPScan

ALL_TOOLS: List[Tool] = [
    SubdomainPermute(),
    JwtCrack(),
    XxeProbe(),
    SsrfProbe(),
    CloudMetadataCredentialProbe(),
    K8sSaTokenTheft(),
    OpenvpnProbe(),
    ActuatorProbe(),
    OpenRedirectProbe(),
    AclBypassProbe(),
    NmapScan(),
    NmapVulnScan(),
    Subfinder(),
    Amass(),
    Cero(),
    Cewl(),
    AsnDiscovery(),
    Dnsx(),
    DnsAxfr(),
    DockerApiProbe(),
    DorkSearchProbe(),
    Subzy(),
    HttpxProbe(),
    Hydra(),
    CacheDeceptionProbe(),
    CachePoisonProbe(),
    WhatWeb(),
    Webanalyze(),
    Wafw00f(),
    TestSsl(),
    Ffuf(),
    FfufVhost(),
    Katana(),
    Nuclei(),
    NosqlInjectionProbe(),
    Gau(),
    Arjun(),
    Sqlmap(),
    Ghauri(),
    Dalfox(),
    DanglingResourceProbe(),
    Corsy(),
    CrlfInjectionProbe(),
    RetireJs(),
    Subjs(),
    LinkFinder(),
    Gowitness(),
    PlaywrightEngine(),
    SpaCrawl(),
    GraphqlIntrospect(),
    Clairvoyance(),
    JwtAnalyze(),
    ShodanInternetdb(),
    FaviconCorrelator(),
    Cloudenum(),
    Cloudfox(),
    PacuEnum(),
    PacuExploit(),
    ScoutsuiteAudit(),
    TrivyScan(),
    TrivyK8sScan(),
    TruffleHog(),
    UnauthDatastoreProbe(),
    WPScan(),
    Commix(),
    Tplmap(),
    Cloudfail(),
    RegistryTagEnum(),
    FirebaseProbe(),
    AzureTenantRecon(),
    BucketPermissionExploit(),
    BucketPermissionProbe(),
    Kiterunner(),
    Searchsploit(),
    GitDumper(),
    HttpRequest(),
    HttpWriteRequest(),
    HttpSmugglingProbe(),
    Smuggler(),
    Interactsh(),
    JenkinsUnauthProbe(),
    TeamCityAuthBypassProbe(),
    TcpProbe(),
    AnonServiceProbe(),
    SmtpProbe(),
    EmailAuthPosture(),
    ResponseSecurityAudit(),
    GitDorker(),
    IdorProbe(),
    IliasRceProbe(),
    MailAccessProbe(),
    MagentoCosmicStingProbe(),
    AuthBootstrap(),
    PathTraversalProbe(),
    PerimeterGatewayProbe(),
    PhpLfi(),
    Phpggc(),
    PhpCgiArgInjectionProbe(),
    LaravelExploit(),
    DeserializationProbe(),
    DeserializationProbeDotnet(),
    FormFuzzer(),
    FastcgiExploit(),
    IdentityAuthBypass(),
    SqliLogin(),
    SshKeyReuseProbe(),
    WebshellUpload(),
    Kubectl(),
    KubectlExploit(),
    KubeHunterEnum(),
    KubeHunterExploit(),
    Kerbrute(),
    KerbruteSpray(),
    PowerView(),
    Bloodhound(),
    Linpeas(),
    Winpeas(),
    LocalCredentialHarvest(),
    PodExecEnum(),
    NetexecEnum(),
    NetexecExploit(),
    CertipyEnum(),
    CertipyExploit(),
    Coercer(),
    Kerberoast(),
    Secretsdump(),
    Ticketer(),
    RaceConditionProbe(),
    SensitiveFileProbe(),
    MassAssignmentProbe(),
    HostHeaderInjectionProbe(),
    DependencyConfusionProbe(),
    OauthRedirectProbe(),
    ServerlessExposureProbe(),
    PrototypePollutionProbe(),
    WebsocketSecurityProbe(),
    CsrfProbe(),
    Cupp(),
    SamlSignatureBypassProbe(),
    CicdExposureProbe(),
    ArtifactRepoExposureProbe(),
    OpenApiSpecDiscoveryProbe(),
    OpenApiFuzz(),
    CloudIdentityPoolProbe(),
    JwtAlgorithmConfusionProbe(),
    JwtTool(),
    GraphqlAuthzProbe(),
    PriceManipulationProbe(),
    EmailHeaderInjectionProbe(),
    RedisRceExploit(),
    JupyterExposureProbe(),
    NtlmInfoDisclosureProbe(),
    ApiVersionShadowProbe(),
    HppProbe(),
    WorkflowStepBypassProbe(),
    CMSeeK(),
    AiStackProbe(),
    CveIntelEnricher(),
    CyberPanelRceProbe(),
    CraftcmsTransformRceProbe(),
    DrupalJsonapiSqliProbe(),
    FlowiseTokenLeakProbe(),
    UnixPrivescExploit(),
    KernelPrivescExploit(),
]


def by_name() -> Dict[str, Tool]:
    return {t.spec.name: t for t in ALL_TOOLS}


def openai_tool_schema(tool: Tool) -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.spec.name,
            "description": tool.spec.description,
            "parameters": tool.spec.parameters,
        },
    }


def openai_tool_schemas(tools: Iterable[Tool] = ALL_TOOLS) -> List[Dict[str, Any]]:
    """Render a set of tools (ALL_TOOLS by default) as OpenAI-style
    function-calling definitions. The execution loop passes its own
    per-run tool map (which also includes memory tools bound to that
    run) instead of relying on the default."""
    return [openai_tool_schema(t) for t in tools]
