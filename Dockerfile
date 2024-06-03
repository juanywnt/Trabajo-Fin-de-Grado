# Use Python 3.9.19 as base image
FROM python:3.9.19-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install dependencies using pip
RUN pip install --no-cache-dir -r requirements.txt

# Install wget, tar, xz and other necessary packages
RUN apk add --no-cache wget tar xz

# Specify versions for pandoc and texlive
ARG PANDOC_VERSION=2.11.4

# Install specific version of pandoc
RUN wget https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}/pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz \
    && tar xvzf pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz \
    && cp -r pandoc-${PANDOC_VERSION}/bin/* /usr/local/bin/ \
    && rm -rf pandoc-${PANDOC_VERSION} pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz

# Install texlive without unnecessary packages
RUN apk add --no-cache texlive-full

# Clean up APK cache
RUN rm -rf /var/cache/apk/*

# Copy the credentials file to the path needed for AWS CLI
COPY credentials /root/.aws/credentials

# Copy the application code into the container at /app
COPY . /app/

# Run the application
CMD ["python", "main.py"]
