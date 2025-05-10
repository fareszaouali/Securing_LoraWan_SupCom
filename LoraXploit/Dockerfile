FROM golang:latest

# Install Python 3, pip, and other necessary tools
RUN apt-get update && apt-get install -y python3-pip python3-venv

# Set the working directory to /app
WORKDIR /root/app
ENV PYTHONPATH="/root/app" \
    GOPATH="/root/go"

# Create a virtual environment for Python
RUN python3 -m venv /root/venv

# Set environment variables for virtual environment
ENV PATH="/root/venv/bin:$PATH"

# Add the python requirements first in order to docker cache them
ADD ./requirements.txt /root/app/requirements.txt

# Install the Python dependencies inside the virtual environment
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Copy the current directory contents into the container at /app
ADD . /root/app/

# Initialize Go module with a local module path
RUN go mod init example.com/project  # Local module path

# Install Go dependencies
RUN go get -d ./...

# Ensure python points to python3 (skip removal if not needed)
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Compile go library
WORKDIR /root/app/tools/lorawanwrapper/utils
RUN go build -o lorawanWrapper.so -buildmode=c-shared *.go
#RUN bash -c "go build -o lorawanWrapper.so -buildmode=c-shared *.go"

# Set the final working directory back to /root/app
WORKDIR /root/app

# Keep the container running (for debugging purposes, can be changed later)
CMD sleep infinity
