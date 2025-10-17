FROM nucypher/rust-python:3.13.7

# set default user
USER $USER

# update os
RUN sudo apt-get update -y
RUN sudo apt-get full-upgrade -y

# install git (for git dependencies)
RUN sudo apt-get install -y git

# set default in-container workdir
WORKDIR /code

# Layer 1: Install dependencies
COPY requirements.txt /code
RUN pip3 install --upgrade pip
RUN pip3 install --no-cache-dir -r requirements.txt

# Layer 2: Install porter entrypoint
COPY . /code
RUN pip3 install . --no-deps

# Layer 3: Set environment variables
RUN export PATH="$HOME/.local/bin:$PATH"
CMD ["/bin/bash"]
