# swi2

Analysis of data and writeup: https://jordanjoewatson.github.io/2022/09/04/detecting_c2_channels

SWI Prolog Threat Hunting tool, to identify Command and Control (C2) channels. Identifies C2 channels such as Cobalt Strike beacons with varying delay and jitter by examining entropy of time between consequitive network request.

## Usage (Docker):

````
docker build -t example .
docker run -t -d example bash
docker container ls 
docker container exec -it <containername> bash
swipl main.pl # Or prolog main.pl if that doesn't work
````

## Usage (Without Docker):

````
prolog main.pl
import_netlogs('data/beacondata.csv').
search(T,S,D,100,[]).
````
