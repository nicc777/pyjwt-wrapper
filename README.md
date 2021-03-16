# pyjwt-wrapper

An easy to use wrapper around PyJWT for authentication and authorization.

**_Note_**: This project just started, so still in a very early development stage. Nothing is to be considered stable. Not for production use.

## Testing from Source

Basic steps:

1. Clone the repository
2. Create a Python Virtual Environment
3. Install dependencies
4. Run the unit tests
5. Get teh coverage reports

The steps above can all be summarized in the following list of Unix commands (bash or zsh):

```shell
# Clone the repository
git clone https://github.com/nicc777/pyjwt-wrapper.git

cd pyjwt-wrapper

# Create a Python Virtual Environment
python -m venv venv

. venv/bin/activate

# Install dependencies
pip install pyjwt coverage

# Run the unit tests
coverage run -m unittest discover

# Get teh coverage reports
coverage report -m
```
