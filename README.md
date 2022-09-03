# swi2

SWI Prolog Threat Hunting tool, to identify Command and Control (C2) channels. Identifies C2 channels such as Cobalt Strike beacons with varying delay and jitter by examining entropy of time between consequitive network request 

## Usage:

````
prolog main.pl
import_netlogs('./f/redditdata.csv').
search(T,S,D,40,[]).
````
