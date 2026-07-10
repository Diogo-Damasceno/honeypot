# Honeypot SSH/HTTP 🍯

Honeypot de **baixa interação** que simula servidores SSH e HTTP falsos para atrair e **registrar tentativas de ataque** — IP de origem, credenciais testadas, User-Agent, método/caminho HTTP e horário — armazenando tudo em SQLite e gerando estatísticas.

> ⚠️ Ferramenta educacional/defensiva. Um honeypot **nunca** concede acesso real: apenas responde de forma convincente e registra. Rode em ambiente controlado; exponha à internet por sua conta e risco.

## Recursos

- Servidor **SSH falso** com banner realista (OpenSSH) — captura o banner do cliente
- Servidor **HTTP falso** (nginx 401) — captura método, caminho, User-Agent e credenciais Basic Auth
- Registro persistente em **SQLite** (IP, porta, usuário, senha, UA, timestamp UTC)
- **Estatísticas**: top IPs atacantes, usuários e senhas mais tentados
- Multithread, sem dependências externas (stdlib pura)

## Instalação

```bash
git clone https://github.com/Diogo-Damasceno/honeypot.git
cd honeypot
pip install -e .
```

## Uso

```bash
# iniciar (portas altas não exigem root)
honeypot --ssh-port 2222 --http-port 8080

# ver estatísticas do banco
honeypot --stats --db honeypot.db
```

Para escutar nas portas reais 22/80 é preciso privilégio (não recomendado no mesmo host que seu SSH real):

```bash
sudo honeypot --ssh-port 22 --http-port 80
```

### Testar manualmente

```bash
# dispara um evento HTTP
curl -u admin:123456 http://localhost:8080/wp-admin

# dispara um evento SSH (captura o banner)
nc localhost 2222
```

## Testes

```bash
pip install -e '.[dev]'
pytest -q
```

## Arquitetura

```
honeypot/
├── store.py     # persistência SQLite + estatísticas
├── servers.py   # servidores falsos SSH/HTTP (baixa interação)
└── cli.py       # interface de linha de comando
```

## Próximos passos (ideias)

- Enriquecimento com geolocalização de IP (GeoLite2)
- Exportação para o Threat Intelligence Platform (outro projeto do portfólio)
- Dashboard web em tempo real

## Licença

MIT
