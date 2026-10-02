# ESA 回源 IP 自动同步

自动把阿里云 ESA 的最新回源 IP 白名单同步到 ECS 安全组的前缀列表。

## 快速开始

1. 安装依赖

   ```bash
   python -m pip install -r requirements.txt
   ```

2. 复制配置模板

   ```bash
   cp .env.example .env
   chmod 600 .env
   ```

3. 编辑 `.env`，填入阿里云凭证、ESA 站点 ID、ECS 安全组 ID

4. 运行
   ```bash
   python app.py
   ```

## 定时执行

cron 示例（每天凌晨 3 点）：

```bash
0 3 * * * /usr/local/bin/python3.11 /path/to/app.py >> /var/log/esa-sync.log 2>&1
```

## 所需 RAM 权限

建议使用 RAM 子账号，只授予必要权限：

```
esa:GetOriginProtection
esa:UpdateOriginProtectionIpWhiteList
ecs:CreatePrefixList
ecs:DeletePrefixList
ecs:DescribePrefixLists
ecs:DescribeSecurityGroupAttribute
ecs:AuthorizeSecurityGroup
ecs:RevokeSecurityGroup
```

## 工作原理

1. 调用 ESA `GetOriginProtection` 获取最新回源 IP 白名单
2. 若 `NeedUpdate` 为 false，说明已是最新，直接退出
3. 否则：清理安全组中所有引用"受管前缀列表"的规则 → 删除这些前缀列表
4. 用最新白名单创建新的 IPv4 / IPv6 前缀列表
5. 将新前缀列表绑定到安全组的指定端口
6. 调用 ESA `UpdateOriginProtectionIpWhiteList` 确认更新
