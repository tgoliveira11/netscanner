# pfSense-pkg-NetScanner

Pacote pfSense no mesmo estilo do [pfSense-pkg-RESTAPI](https://github.com/pfrest/pfSense-pkg-RESTAPI): instala com **um comando** no shell, configura na GUI.

## Instalação (pfSense)

No prompt do pfSense (SSH ou console), como root:

**pfSense CE 2.8.x** (ajuste a versão conforme [releases](https://github.com/netscanner/netscanner/releases)):

```bash
pkg-static add https://github.com/netscanner/netscanner/releases/latest/download/pfSense-2.8.1-pkg-NetScanner.pkg
```

**pfSense Plus** (exemplo):

```bash
pkg-static -C /dev/null add https://github.com/netscanner/netscanner/releases/latest/download/pfSense-26.03.1-pkg-NetScanner.pkg
```

> Antes de instalar, confirme que existe um `.pkg` compilado para a **sua** versão do pfSense na página de releases. Instalar build incompatível pode falhar ou deixar o sistema instável.

Depois da instalação:

1. **Services → NetScanner Settings**
2. Ative **Enable NetScanner push**
3. **Agent URL** — ex. `http://192.168.51.106:4000`
4. **Push token** — mesmo valor que `PFSENSE_PUSH_TOKEN` no agente
5. **Save**

Status e push manual: **Services → NetScanner**.

## Pré-requisitos no agente (Mac)

Em `~/.netscanner/config.env`:

```env
PFSENSE_PUSH_TOKEN=<segredo-longo>
GATEWAY_HOST=0.0.0.0
```

## Build do `.pkg` no pfSense (antes de publicar release)

Copie só a pasta do pacote para o firewall:

```bash
scp -r integrations/pfsense/pfSense-pkg-NetScanner root@192.168.51.1:/tmp/
```

No pfSense:

```bash
cd /tmp/pfSense-pkg-NetScanner
make package
pkg-static -C /dev/null add work/pkg/pfSense-pkg-NetScanner-0.1.0.pkg
```

Para gerar o nome usado nas releases:

```bash
python3 tools/make_package.py --tag 0.1.0 --pfsense-version "$(cat /etc/version | awk '{print $1}')"
```

## Estrutura (igual ao REST API)

```
pfSense-pkg-NetScanner/
  Makefile
  pkg-plist
  pkg-descr
  pkg-install.in          # regista pacote via /etc/rc.packages
  pkg-deinstall.in
  files/
    usr/local/pkg/netscanner.xml
    usr/local/pkg/netscanner.inc
    usr/local/bin/netscanner-collect*
    usr/local/www/packages/netscanner/
    ...
tools/
  make_package.py
  install-on-pfsense.sh
```

## API no agente

```
POST /api/integrations/pfsense/push
Authorization: Bearer <PFSENSE_PUSH_TOKEN>
```

```
GET /api/integrations/pfsense/status
```

## CLI opcional (após instalar o pacote)

```bash
/usr/local/bin/php /usr/local/pkg/configure-pfsense.php http://192.168.51.106:4000 SEU_TOKEN
/usr/local/bin/netscanner-collect
tail -f /var/log/netscanner-push.log
```

## Desinstalar

**System → Package Manager → NetScanner → Delete**

## Dados enviados

- DHCP leases (todas VLANs)
- Tabela ARP
- Gateways WAN / multi-WAN
- Interfaces e VLANs
- Mapeamentos DHCP estáticos
- Versão e hostname pfSense
