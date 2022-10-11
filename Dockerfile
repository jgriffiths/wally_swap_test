FROM python:3.9-slim-bullseye

EXPOSE 50051

# Setup virtual env
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install dependencies
COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

# Install the test harness source code
COPY *.py ./

# Run the main file
CMD ["python3", "main.py"]
