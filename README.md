# libwally swap test harness

An example test harness for executing 3-step swaps using PSET via wally and gdk.

Development/Experimental code, please take care to test thoroughly if adapting/integrating this code with your own projects.

## Installation

Create a python3 virtual environment and install the dependencies:

```
$ virtualenv venv
$ source ./venv/bin/activate
$ pip install -r requirements.txt
```

## Configuring

Edit the configuration variables in `utils.py` to match the scenario you wish to test.

By default the harness will perform a swap of the AMP asset TEST with L-BTC in an AMP subaccount.

## Running

Run the test via `main.py`:

```
$ python main.py
```

## Docker

You can run the test harness under docker if your environment isn't suitable for whatever reason.

Edit `utils.py` as needed then:

```
docker build -t wally-swap-test .
docker run wally-swap-test
```
