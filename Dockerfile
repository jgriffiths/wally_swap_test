FROM python:3.9-slim-bullseye

EXPOSE 50051

# set up virtual env
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# deps
COPY *.whl ./
COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

# Python source code
COPY *.py ./

# run the main file
CMD ["python3", "main.py"]

