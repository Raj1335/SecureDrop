"""
SecureDrop Interactive CLI
"""

import click
import sys
import socket
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.validation import Validator, ValidationError

console = Console()

class IPValidator(Validator):
    def validate(self, document):
        text = document.text
        if not text:
            raise ValidationError(message="IP address required")
        
        parts = text.split('.')
        if len(parts) != 4:
            raise ValidationError(message="Invalid IP format (use xxx.xxx.xxx.xxx)")
        
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    raise ValidationError(message=f"Invalid IP octet: {num}")
        except ValueError:
            raise ValidationError(message="IP must contain only numbers and dots")

class CodeValidator(Validator):
    def validate(self, document):
        text = document.text
        if not text:
            raise ValidationError(message="Pairing code required")
        if len(text) != 6:
            raise ValidationError(message="Code must be 6 digits")
        if not text.isdigit():
            raise ValidationError(message="Code must be numeric")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def show_banner():
    panel = Panel(
        "[cyan]Secure P2P File Transfer[/cyan]\n"
        "[dim]SPAKE2 • X25519 • ChaCha20-Poly1305[/dim]",
        title="[bold cyan]SecureDrop v1.0[/bold cyan]",
        border_style="cyan",
    )
    console.print(panel)

def find_file_by_name(filename):
    """Search for file in current dir and common locations"""
    search_paths = [
        Path.cwd(),
        Path.home() / "Downloads",
        Path.home() / "Documents",
        Path.home() / "Desktop",
    ]
    
    matches = []
    for base_path in search_paths:
        if not base_path.exists():
            continue
        # Search recursively up to 2 levels deep
        for depth in range(3):
            pattern = "*/" * depth + filename
            matches.extend(base_path.glob(pattern))
            if matches:
                break
        if matches:
            break
    
    return matches

def select_files_interactive():
    """Interactive file selection - space/comma separated or search by name"""
    console.print("\n[cyan]📁 Select Files[/cyan]")
    console.print("[dim]Enter: full paths, filenames, or space/comma separated[/dim]")
    console.print("[dim]Tab for autocomplete, Ctrl+C to cancel[/dim]")
    
    file_completer = PathCompleter(expanduser=True)
    
    try:
        input_str = pt_prompt(
            "Files: ",
            completer=file_completer,
            complete_while_typing=True
        ).strip()
        
        if not input_str:
            console.print("[yellow]No files specified[/yellow]")
            return None
        
        # Split by space or comma
        file_inputs = [f.strip() for f in input_str.replace(',', ' ').split()]
        
        files = []
        for file_input in file_inputs:
            path = Path(file_input).expanduser()
            
            # If it's a valid path, use it
            if path.exists() and path.is_file():
                files.append(path)
                size = path.stat().st_size / (1024 * 1024)
                console.print(f"  [green]✓[/green] {path.name} ({size:.1f} MB)")
                continue
            
            # Otherwise, search by filename
            matches = find_file_by_name(file_input)
            
            if not matches:
                console.print(f"[red]✗ Not found: {file_input}[/red]")
                continue
            
            if len(matches) == 1:
                # Single match - use it
                path = matches[0]
                files.append(path)
                size = path.stat().st_size / (1024 * 1024)
                console.print(f"  [green]✓[/green] {path.name} ({size:.1f} MB) [dim]{path.parent}[/dim]")
            else:
                # Multiple matches - let user choose
                console.print(f"\n[yellow]Multiple matches for '{file_input}':[/yellow]")
                for idx, match in enumerate(matches[:5], 1):
                    size = match.stat().st_size / (1024 * 1024)
                    console.print(f"  {idx}. {match.name} ({size:.1f} MB) [dim]{match.parent}[/dim]")
                
                if len(matches) > 5:
                    console.print(f"  [dim]... and {len(matches) - 5} more[/dim]")
                
                choice = Prompt.ask("Select", choices=[str(i) for i in range(1, min(6, len(matches)+1))])
                selected = matches[int(choice) - 1]
                files.append(selected)
                size = selected.stat().st_size / (1024 * 1024)
                console.print(f"  [green]✓[/green] {selected.name} ({size:.1f} MB)")
        
        if not files:
            console.print("[yellow]No valid files selected[/yellow]")
            return None
        
        total_size = sum(f.stat().st_size for f in files) / (1024 * 1024)
        console.print(f"\n[green]✓ {len(files)} file(s) ({total_size:.1f} MB)[/green]")
        return files
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        return None
    except EOFError:
        return None

@click.group(invoke_without_command=True)
@click.pass_context
@click.option('--version', is_flag=True, help='Show version')
def main(ctx, version):
    """SecureDrop - Secure P2P File Transfer"""
    if version:
        console.print("SecureDrop v1.0.0")
        return
    
    if ctx.invoked_subcommand is None:
        show_banner()
        
        console.print("\n[bold]Mode:[/bold]")
        console.print("  [cyan]1.[/cyan] Send files")
        console.print("  [cyan]2.[/cyan] Receive files")
        console.print("  [cyan]3.[/cyan] Exit")
        
        choice = Prompt.ask("\nSelect", choices=["1", "2", "3"], default="1")
        
        if choice == "1":
            ctx.invoke(send)
        elif choice == "2":
            ctx.invoke(receive)
        else:
            console.print("Goodbye!")

@main.command()
@click.option('--ip', help='Receiver IP address')
@click.option('--code', help='6-digit pairing code')
@click.option('--files', multiple=True, help='Files to send')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
def send(ip, code, files, verbose):
    """Send files to a receiver"""
    show_banner()
    
    # Get receiver IP
    if not ip:
        console.print("\n[cyan]🌐 Receiver IP[/cyan]")
        console.print("[dim]Example: 192.168.1.5[/dim]")
        try:
            ip = pt_prompt("IP: ", validator=IPValidator()).strip()
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled[/yellow]")
            return
    
    # Get pairing code
    if not code:
        console.print("\n[cyan]🔑 Pairing Code[/cyan]")
        console.print("[dim]6-digit code from receiver[/dim]")
        try:
            code = pt_prompt("Code: ", validator=CodeValidator()).strip()
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled[/yellow]")
            return
    
    # Test connection early
    console.print("\n[dim]Testing connection...[/dim]")
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_sock.settimeout(5)
    try:
        test_sock.connect((ip, 5000))
        test_sock.close()
        console.print("[green]✓ Receiver reachable[/green]")
    except socket.timeout:
        console.print(f"[red]✗ Connection timeout to {ip}:5000[/red]")
        console.print("[yellow]Check: Is receiver running? Correct IP?[/yellow]")
        return
    except ConnectionRefusedError:
        console.print(f"[red]✗ Connection refused by {ip}:5000[/red]")
        console.print("[yellow]Check: Is receiver running on port 5000?[/yellow]")
        return
    except OSError as e:
        console.print(f"[red]✗ Cannot reach {ip}:5000[/red]")
        console.print(f"[yellow]Check: Same network? Firewall? ({e})[/yellow]")
        return
    finally:
        try:
            test_sock.close()
        except:
            pass
    
    # Select files
    if not files:
        file_list = select_files_interactive()
        if not file_list:
            return
    else:
        file_list = []
        for f in files:
            path = Path(f).expanduser()
            if path.exists() and path.is_file():
                file_list.append(path)
            else:
                matches = find_file_by_name(f)
                if matches:
                    file_list.append(matches[0])
                else:
                    console.print(f"[red]✗ Not found: {f}[/red]")
                    return
    
    # Import and run sender
    try:
        from .sender_module import SecureSender
        
        sender = SecureSender(ip, code, verbose=verbose)
        success = sender.send_files(file_list, console)
        
        sys.exit(0 if success else 1)
        
    except ImportError:
        console.print("[red]✗ Sender module not found[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)

@main.command()
@click.option('--port', default=5000, help='Port to listen on')
@click.option('--save-dir', default='received_files', help='Save directory')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
def receive(port, save_dir, verbose):
    """Receive files from a sender"""
    show_banner()
    
    try:
        from .receiver_module import SecureReceiver
        
        receiver = SecureReceiver(port=port, save_dir=save_dir, verbose=verbose)
        receiver.start(console)
        
    except ImportError:
        console.print("[red]✗ Receiver module not found[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)

@main.command()
def info():
    """Show protocol information"""
    show_banner()
    
    features = Table(title="Security Features", show_header=False, box=None)
    features.add_column(style="cyan")
    features.add_column(style="white")
    
    features.add_row("🔐 PAKE", "SPAKE2 (offline brute-force resistant)")
    features.add_row("🔑 Key Exchange", "X25519 ephemeral DH (forward secrecy)")
    features.add_row("🔒 Encryption", "ChaCha20-Poly1305 AEAD")
    features.add_row("✅ MITM Detection", "SAS verification")
    features.add_row("🌐 Network", "Local network only")
    
    console.print(features)
    console.print()
    
    panel = Panel(
        "[bold]Receiver:[/bold]\n"
        "  $ securedrop receive\n\n"
        "[bold]Sender:[/bold]\n"
        "  $ securedrop send",
        title="Quick Start",
        border_style="cyan",
    )
    console.print(panel)

if __name__ == "__main__":
    main()