#!/bin/sh

grep -v 'Executing consumer group command failed' $1 | egrep '^[a-zA-Z_\-\:\=]+([\.;][a-zA-Z_\-\:\=]+)+ [+-]?([0-9]*[.])?[0-9]+ [0-9]+$' > $1.exclude
