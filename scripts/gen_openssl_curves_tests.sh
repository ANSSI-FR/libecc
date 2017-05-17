#/*
# *  Copyright (C) 2017 - This file is part of libecc project
# *
# *  Authors:
# *      Ryad BENADJILA <ryadbenadjila@gmail.com>
# *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
# *      Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
# *
# *  Contributors:
# *      Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
# *      Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
# *
# *  This software is licensed under a dual BSD and GPL v2 license.
# *  See LICENSE file at the root folder of the project.
# */
#!/bin/sh

CURVES=`openssl ecparam -list_curves | grep prime | cut -d':' -f1 | tr '\n' ' '`

for curve in $CURVES
do
	echo "Adding $curve"
	openssl ecparam -param_enc explicit -outform DER -name $curve -out "$curve".der
	python expand_libecc.py --name="$curve" --ECfile="$curve".der --add-test-vectors=2
	rm "$curve".der
done
