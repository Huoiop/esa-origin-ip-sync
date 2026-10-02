import os
from dotenv import load_dotenv

from alibabacloud_esa20240910.client import Client as EsaClient
from alibabacloud_esa20240910 import models as esa_models
from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_ecs20140526 import models as ecs_models
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_tea_util import models as util_models


# ==================== 加载 .env ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))


# ==================== 配置读取 ====================
def _require(key: str) -> str:
    """读取必填的环境变量，缺失时报错退出。"""
    val = os.environ.get(key)
    if not val:
        raise SystemExit(f"✘ 缺少环境变量: {key}，请在 .env 中配置")
    return val


# --- 阿里云凭证（SDK 会直接读环境变量，这里只做一次校验）---
_require('ALIBABA_CLOUD_ACCESS_KEY_ID')
_require('ALIBABA_CLOUD_ACCESS_KEY_SECRET')

# --- ESA ---
ESA_SITE_ID = int(_require('ESA_SITE_ID'))

# --- ECS ---
REGION_ID = _require('ECS_REGION_ID')
SG_ID = _require('ECS_SECURITY_GROUP_ID')

# --- 前缀列表命名 ---
NEW_PREFIX_LIST_NAME_V4 = _require('PREFIX_LIST_NAME_V4')
NEW_PREFIX_LIST_NAME_V6 = _require('PREFIX_LIST_NAME_V6')
PREFIX_LIST_DESC = os.environ.get(
    'PREFIX_LIST_DESCRIPTION', 'ESA源站防护最新回源IP白名单'
)

# --- 受管前缀列表的识别前缀 ---
MANAGED_NAME_PREFIX = os.environ.get('MANAGED_NAME_PREFIX', 'ESA')

# --- 安全组规则 ---
# PORTS 用逗号分隔，例如 "443/443,80/80"
PORTS = [p.strip() for p in _require('SECURITY_GROUP_PORTS').split(',') if p.strip()]
IP_PROTOCOL = os.environ.get('SECURITY_GROUP_IP_PROTOCOL', 'TCP')
NIC_TYPE = os.environ.get('SECURITY_GROUP_NIC_TYPE', 'intranet')


# ==================== 客户端 ====================
def create_esa_client() -> EsaClient:
    config = open_api_models.Config(
        access_key_id=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID'),
        access_key_secret=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
    )
    config.endpoint = os.environ.get('ESA_ENDPOINT', 'esa.cn-hangzhou.aliyuncs.com')
    return EsaClient(config)


def create_ecs_client() -> EcsClient:
    config = open_api_models.Config(
        access_key_id=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID'),
        access_key_secret=os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET'),
    )
    config.endpoint = f'ecs.{REGION_ID}.aliyuncs.com'
    return EcsClient(config)


# ==================== Step 1: 获取 ESA 信息（含 NeedUpdate） ====================
def step1_get_esa_ips():
    print("\n" + "=" * 60)
    print("Step 1: 获取 ESA 最新回源 IP 白名单")
    print("=" * 60)
    client = create_esa_client()
    request = esa_models.GetOriginProtectionRequest(site_id=ESA_SITE_ID)
    response = client.get_origin_protection_with_options(
        request, util_models.RuntimeOptions()
    )
    body = response.body

    ipv4_list, ipv6_list = [], []
    if body.latest_ipwhitelist:
        if body.latest_ipwhitelist.ipv_4:
            ipv4_list = list(body.latest_ipwhitelist.ipv_4)
        if body.latest_ipwhitelist.ipv_6:
            ipv6_list = list(body.latest_ipwhitelist.ipv_6)

    need_update = body.need_update
    print(f"IPv4: {len(ipv4_list)} 条")
    print(f"IPv6: {len(ipv6_list)} 条")
    print(f"NeedUpdate: {need_update}")
    return ipv4_list, ipv6_list, need_update


# ==================== Step 2: 动态发现 + 清理 ====================
def _discover_prefix_list_refs(sg_id):
    client = create_ecs_client()
    request = ecs_models.DescribeSecurityGroupAttributeRequest(
        region_id=REGION_ID,
        security_group_id=sg_id,
        direction='ingress',
    )
    response = client.describe_security_group_attribute_with_options(
        request, util_models.RuntimeOptions()
    )
    perms = response.body.permissions.permission if response.body.permissions else []

    refs = {}
    for p in perms:
        pl_id = p.source_prefix_list_id
        if not pl_id:
            continue
        refs.setdefault(pl_id, []).append({
            'port_range': p.port_range,
            'ip_protocol': p.ip_protocol,
            'nic_type': getattr(p, 'nic_type', None) or NIC_TYPE,
            'policy': getattr(p, 'policy', None) or 'accept',
        })
    return refs


def _get_prefix_list_name(pl_id):
    client = create_ecs_client()
    request = ecs_models.DescribePrefixListsRequest(
        region_id=REGION_ID,
        prefix_list_id=pl_id,
    )
    runtime = util_models.RuntimeOptions()
    try:
        if hasattr(client, 'describe_prefix_lists_with_options'):
            resp = client.describe_prefix_lists_with_options(request, runtime)
        else:
            resp = client.describe_prefix_list_with_options(request, runtime)
    except Exception:
        return None
    lists = resp.body.prefix_lists.prefix_list if resp.body.prefix_lists else []
    return lists[0].prefix_list_name if lists else None


def _revoke_rule(sg_id, pl_id, port_range, ip_protocol, nic_type, policy):
    client = create_ecs_client()
    request = ecs_models.RevokeSecurityGroupRequest(
        region_id=REGION_ID,
        security_group_id=sg_id,
        source_prefix_list_id=pl_id,
        ip_protocol=ip_protocol,
        port_range=port_range,
        nic_type=nic_type,
        policy=policy,
    )
    return client.revoke_security_group_with_options(
        request, util_models.RuntimeOptions()
    ).body.request_id


def _delete_prefix_list(pl_id):
    client = create_ecs_client()
    request = ecs_models.DeletePrefixListRequest(
        region_id=REGION_ID,
        prefix_list_id=pl_id,
    )
    return client.delete_prefix_list_with_options(
        request, util_models.RuntimeOptions()
    ).body.request_id


def step2_cleanup_old_prefix_lists(sg_id):
    print("\n" + "=" * 60)
    print("Step 2: 动态发现并清理安全组中的旧前缀列表")
    print("=" * 60)

    refs = _discover_prefix_list_refs(sg_id)
    if not refs:
        print("  安全组未引用任何前缀列表，无需清理。")
        return

    managed = []
    for pl_id in refs:
        name = _get_prefix_list_name(pl_id) or ''
        if name.startswith(MANAGED_NAME_PREFIX):
            managed.append(pl_id)
            print(f"  受管前缀列表: {pl_id} ({name}), 关联规则 {len(refs[pl_id])} 条")
        else:
            print(f"  跳过节外前缀列表: {pl_id} ({name})")

    if not managed:
        print("  未发现需要清理的受管前缀列表。")
        return

    for pl_id in managed:
        for rule in refs[pl_id]:
            try:
                _revoke_rule(sg_id, pl_id, rule['port_range'],
                             rule['ip_protocol'], rule['nic_type'], rule['policy'])
                print(f"    ✔ 已删规则: {pl_id} 端口 {rule['port_range']}")
            except Exception as e:
                if 'NotFound' in str(e):
                    print(f"    ⚠ 规则不存在（忽略）: {pl_id} 端口 {rule['port_range']}")
                else:
                    print(f"    ✘ 删除规则失败: {pl_id} 端口 {rule['port_range']}: {e}")

    for pl_id in managed:
        try:
            _delete_prefix_list(pl_id)
            print(f"    ✔ 已删除前缀列表: {pl_id}")
        except Exception as e:
            print(f"    ✘ 删除前缀列表失败: {pl_id}: {e}")


# ==================== Step 3: 创建新前缀列表 ====================
def _create_prefix_list(name, address_family, cidrs):
    if not cidrs:
        return None
    client = create_ecs_client()
    entries = [
        ecs_models.CreatePrefixListRequestEntry(
            cidr=cidr,
            description=f'ESA {address_family} entry',
        )
        for cidr in cidrs
    ]
    request = ecs_models.CreatePrefixListRequest(
        region_id=REGION_ID,
        max_entries=len(cidrs),
        address_family=address_family,
        prefix_list_name=name,
        description=PREFIX_LIST_DESC,
        entry=entries,
    )
    return client.create_prefix_list_with_options(
        request, util_models.RuntimeOptions()
    ).body.prefix_list_id


def step3_create_new_prefix_lists(ipv4_cidrs, ipv6_cidrs):
    print("\n" + "=" * 60)
    print("Step 3: 创建新前缀列表")
    print("=" * 60)

    pl_v4 = _create_prefix_list(NEW_PREFIX_LIST_NAME_V4, 'IPv4', ipv4_cidrs)
    print(f"  ✔ IPv4: {pl_v4} ({len(ipv4_cidrs)} 条)")

    pl_v6 = _create_prefix_list(NEW_PREFIX_LIST_NAME_V6, 'IPv6', ipv6_cidrs)
    print(f"  ✔ IPv6: {pl_v6} ({len(ipv6_cidrs)} 条)")

    return pl_v4, pl_v6


# ==================== Step 4: 添加新规则 ====================
def _authorize_rule(sg_id, pl_id, port_range):
    client = create_ecs_client()
    request = ecs_models.AuthorizeSecurityGroupRequest(
        region_id=REGION_ID,
        security_group_id=sg_id,
        ip_protocol=IP_PROTOCOL,
        port_range=port_range,
        source_prefix_list_id=pl_id,
        nic_type=NIC_TYPE,
        policy='accept',
        description=f'ESA节点回源 {port_range}',
    )
    return client.authorize_security_group_with_options(
        request, util_models.RuntimeOptions()
    ).body.request_id


def step4_add_new_rules(sg_id, pl_v4, pl_v6):
    print("\n" + "=" * 60)
    print("Step 4: 添加新规则")
    print("=" * 60)

    prefix_lists = [p for p in [pl_v4, pl_v6] if p]
    ok = fail = 0
    for pl in prefix_lists:
        for port in PORTS:
            try:
                _authorize_rule(sg_id, pl, port)
                print(f"  ✔ 添加 {pl} 端口 {port}")
                ok += 1
            except Exception as e:
                if 'Duplicate' in str(e):
                    print(f"  ⚠ 已存在 {pl} 端口 {port}（忽略）")
                    ok += 1
                else:
                    print(f"  ✘ 添加 {pl} 端口 {port} 失败: {e}")
                    fail += 1
    print(f"  完成：成功 {ok} 条，失败 {fail} 条")
    return fail == 0


# ==================== Step 5: 确认更新 ESA 回源 IP 白名单 ====================
def step5_update_origin_protection_ip_whitelist():
    print("\n" + "=" * 60)
    print("Step 5: 确认更新 ESA 站点回源 IP 白名单到最新版本")
    print("=" * 60)

    client = create_esa_client()
    request = esa_models.UpdateOriginProtectionIpWhiteListRequest(
        site_id=ESA_SITE_ID,
    )
    runtime = util_models.RuntimeOptions()
    try:
        response = client.update_origin_protection_ip_white_list_with_options(
            request, runtime
        )
        print(f"  ✔ 白名单更新已确认，请求ID: {response.body.request_id}")
        return True
    except Exception as e:
        print(f"  ✘ 确认更新失败: {e}")
        return False


# ==================== 主流程 ====================
def main():
    print(">>> 同步 ESA 回源 IP 白名单到 ECS 前缀列表")
    print(f"    ESA 站点: {ESA_SITE_ID}")
    print(f"    ECS 地域: {REGION_ID}")
    print(f"    安全组:   {SG_ID}")

    ipv4_cidrs, ipv6_cidrs, need_update = step1_get_esa_ips()

    if not need_update:
        print("\n" + "=" * 60)
        print("✔ NeedUpdate 为 false，白名单已是最新，无需任何操作。")
        print("=" * 60)
        return

    print("\n⚠ NeedUpdate 为 true，开始执行同步流程…")

    if not ipv4_cidrs and not ipv6_cidrs:
        print("✘ ESA 返回空白名单，终止。")
        raise SystemExit(1)

    step2_cleanup_old_prefix_lists(SG_ID)

    pl_v4, pl_v6 = step3_create_new_prefix_lists(ipv4_cidrs, ipv6_cidrs)
    if not pl_v4 and not pl_v6:
        print("✘ 新前缀列表一个都没创建成功，终止。")
        raise SystemExit(1)

    if not step4_add_new_rules(SG_ID, pl_v4, pl_v6):
        print("✘ 部分规则添加失败，请排查。")

    step5_update_origin_protection_ip_whitelist()

    print("\n" + "=" * 60)
    print("全部完成")
    print("=" * 60)
    print(f"新 IPv4 前缀列表: {pl_v4}")
    print(f"新 IPv6 前缀列表: {pl_v6}")


if __name__ == '__main__':
    main()