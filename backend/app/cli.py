import typer

cli = typer.Typer()

@cli.command()
def hello():
    print("Hello from SentinelVault CLI!")

if __name__ == "__main__":
    cli()
