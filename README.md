# Software-para-varredura-de-portas-TCP-e-UDP-em-uma-rede
Atividade da disciplina de Tópicos Especiais em Tecnologia Dois - Desenvolver um software para realizar varredura de portas TCP e UDP em uma rede.

# 🔍 Advanced Port Scanner Pro

**Descrição**
Ferramenta de varredura de portas TCP e UDP com interface gráfica (Tkinter), suporte a varredura multi-thread, captura simples de banner HTTP e exportação de resultados. Use apenas em redes/equipamentos que você tem permissão para testar.

---

## Requisitos
* Python 3.8+ (recomendado 3.10+)
* `tkinter` (faz parte da stdlib do Python, mas em algumas distros Linux precisa instalar o pacote do sistema)
* Sistema com interface gráfica (não é feita para rodar em modo texto/CLI sem X server)

> **Observação:** O projeto usa somente bibliotecas da biblioteca padrão do Python — não há dependências pip explicitamente necessárias.

---

## Instalação

### Windows

1. Baixe e instale o Python ([https://www.python.org/](https://www.python.org/)) — marque a opção "Add Python to PATH" durante a instalação.
2. Abra o PowerShell ou Prompt de Comando como Administrador (recomendado para varrer portas privilegiadas <1024).
3. Clone o repositório ou baixe o ZIP e extraia:

```powershell
git clone <REPO_URL>
cd advanced-port-scanner
```

4. (Opcional) Crie e ative um ambiente virtual:
```powershell
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
```

5. Execute a aplicação:
```powershell
python port_scanner.py
```

### Linux (Debian/Ubuntu / Fedora / Arch)
1. Instale Python 3 se ainda não tiver.
2. Instale o pacote do Tkinter (nome varia por distribuição):

* Debian / Ubuntu:
```bash
sudo apt update
sudo apt install python3 python3-tk
```

* Fedora / CentOS (dnf/yum):
```bash
sudo dnf install python3-tkinter  # ou sudo yum install python3-tkinter
```

* Arch Linux / Manjaro:
```bash
sudo pacman -Syu tk
```

3. Clone o repositório e entre na pasta:
```bash
git clone <REPO_URL>
cd advanced-port-scanner
```

4. (Opcional) Crie e ative um venv:
```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
```

5. Execute a aplicação (se precisar varrer portas <1024 use `sudo`):
```bash
python3 port_scanner.py
# ou
sudo python3 port_scanner.py
```

> **Nota:** Rodar com `sudo` dará permissão para bind/scan de portas privilegiadas — cuidado e use apenas em sistemas autorizados.


### macOS

1. **Instale o Homebrew** (se ainda não tiver):
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

2. **Instale o Python e o Tcl/Tk (Tkinter)**
```bash
brew update
brew install python
brew install tcl-tk
```

> Observação: em macs com Apple Silicon (M1/M2) o Homebrew normalmente fica em `/opt/homebrew`; em Macs Intel costuma ficar em `/usr/local`.

3. **Certifique-se de usar a versão do Python do Homebrew** (opcional, mas ajuda a garantir que o Tkinter funcione corretamente):
```bash
# Para Apple Silicon
export PATH="/opt/homebrew/bin:$PATH"

# Para Intel
export PATH="/usr/local/bin:$PATH"
```

4. **Clone o repositório e entre na pasta**:
```bash
git clone <REPO_URL>
cd advanced-port-scanner
```

5. **Crie e ative um ambiente virtual (recomendado)**:
```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
```

6. **Execute a aplicação**:
```bash
python3 port_scanner.py
```

**Permissões e comportamento no macOS**

* O macOS pode pedir permissões para acesso à rede ou à interface gráfica. Conceda as permissões necessárias nas Preferências do Sistema > Segurança & Privacidade, se solicitado.
* Se o Tkinter não abrir a janela, verifique se está usando o Python do Homebrew (ou instale a versão oficial do Python em python.org, que já inclui suporte a Tcl/Tk).


## Uso básico

1. Abra a aplicação.
2. Preencha o campo **Target IP** (ex.: `127.0.0.1` ou `192.168.1.100`).
3. Em **Ports** informe um intervalo ou lista separada por vírgulas, ex.: `1-1024`, `22,80,443`, ou use os presets (Common, Web, Full).
4. Escolha o protocolo (`tcp` ou `udp`), configure `Timeout` e `Threads` conforme necessário.
5. Clique em **Start Scan**. Use **Stop Scan** para interromper.
6. Resultados aparecem na tabela e podem ser exportados (`Export Results`).

### Dicas de parâmetros

* `Timeout` (segundos): aumente se a rede estiver lenta ou se muitos pacotes forem perdidos.
* `Threads`: muitos threads tornam a varredura mais rápida, mas aumentam uso de CPU/NET. Para máquinas fracas diminua para 10–20.
* `Full` (1-65535) pode levar muito tempo; prefira scans direcionados quando possível.


## Funcionalidades importantes

* Varredura TCP com tentativa simples de captura de banner (envia `HEAD / HTTP/1.0`).
* Varredura UDP básica (envia pacote vazio e espera resposta) — **pouco confiável**: UDP não garante resposta e muitos hosts/roteadores descartam tráfego.
* Multi-thread para acelerar varreduras.
* Exportação para `.txt` ou `.csv`.
* Presets e diálogo de seleção rápida de serviços.


## Observações técnicas & limitações

* **UDP**: respostas inconsistentes — um porto pode aparecer como `open|filtered` quando não há resposta de ICMP/UDP.
* **Firewall / IDS**: firewalls locais e dispositivos de borda podem bloquear ou falsamente filtrar resultados.
* **Permissões**: varreduras em portas <1024 geralmente exigem privilégios de root/administrador em sistemas Unix.
* **Tcl/Tk Display**: em servidores sem ambiente gráfico a execução falhará com `TclError: no display name and no $DISPLAY environment variable` — use uma máquina com GUI ou `xvfb` (ex.: `xvfb-run python3 port_scanner.py`).
* **Precisão**: esta ferramenta é para testes simples e educacionais; para auditorias completas use ferramentas especializadas como Nmap.


## Criar executável (opcional)

Para distribuir sem exigir que o usuário tenha Python instalado, use o PyInstaller:

```bash
python -m pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed port_scanner.py
```

* O executável ficará em `dist/port_scanner` (ou `dist/port_scanner.exe` no Windows).
* Teste o binário em uma máquina limpa antes de distribuir.


## Segurança e legalidade

**ATENÇÃO:** Varredura de portas e teste de redes sem autorização é ilegal em muitas jurisdições. Use **apenas** em equipamentos e redes que você possui ou para os quais tem permissão explícita.


## Solução de problemas (FAQ)

**1. A janela não abre / erro TclError**
Em servidores sem X, instale um ambiente gráfico ou execute com `xvfb-run`.

**2. Recebo muitos `open|filtered` em UDP**
É comportamento esperado; aumente timeout ou teste com serviços conhecidos.

**3. Banner vazio / sem informação**
Nem todos os serviços retornam banner com `HEAD`. Ajuste o código para protocolos específicos se quiser *banner grab* mais completo.

**4. Erro de permissão ao tentar varrer portas baixas (
<1024)**
No Linux, rode com `sudo`. No Windows, execute o prompt como Administrador.

**5. App demora muito / trava**
Reduza o número de threads e/ou aumente o timeout. Monitore uso de CPU/RAM.
