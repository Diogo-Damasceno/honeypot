# honeypot

Honeypot de **baixa interação** que simula servidores SSH e HTTP falsos para
atrair e **registrar tentativas de ataque** — IP de origem, credenciais testadas,
User-Agent, método/caminho HTTP e horário — armazenando tudo em SQLite e gerando
estatísticas.

> ⚠️ Ferramenta educacional/defensiva. Um honeypot **nunca** concede acesso real:
> apenas responde de forma falsa para observar atacantes.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/honeypot.git
cd honeypot
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/honeypot" ~/.local/bin/honeypot
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# sobe SSH falso (2222) e HTTP falso (8080) e registra tudo
honeypot

# portas custom e so mostra estatisticas
honeypot --ssh-port 2222 --http-port 8080 --stats
```

Por padrão escuta em `0.0.0.0`. **Nunca exponha na internet sem isolamento**
(use uma VM ou container dedicado).

## Licença

MIT — veja `LICENSE`.
