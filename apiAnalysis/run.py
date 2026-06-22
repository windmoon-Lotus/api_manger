from apiAnalysis import init
from apiAnalysis.main import main


if __name__ == '__main__':
    init()
    args = ["-i", "console.example.com.har", "-p", "-f", "har"]
    main(args)