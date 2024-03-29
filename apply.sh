#!/bin/bash

system_start_time=$(date +%s)

echo Please enter the Profile Name[AWS]:
read -r -p "    " profile_name
echo

echo Please enter the Region[AWS] where the system will run:
read -r -p "    " region_name
echo

echo Please enter the Domain Name for web service you want:
read -r -p "    " domain_name
echo

echo "Admin User's email"
read -r -p "    " email
echo

echo "Admin User's username"
read -r -p "    " username
echo

echo "Admin User's password"
read -r -p "    " password
echo

cat << EOF > ./IaC/variables.tf

variable "region" {
    type = string
    default = "$region_name"
}

variable "profile" {
    type = string
    default = "$profile_name"
}

variable "prefix" {
    type = string
    default = "stablespot"
}

variable "domain" {
    type = string
    default = "$domain_name"
}

variable "admin_email" {
    type = string
    default = "$email"
}

variable "admin_username" {
    type = string
    default = "$username"
}

variable "admin_password" {
    type = string
    default = "$password"
}

EOF

zip -j ./IaC/stablespot-create-spot.zip ./Lambda/Creator/lambda_function.py ./Lambda/Selector/tools.py ./Lambda/variables.py
zip -j ./IaC/stablespot-migration-by-interrupt.zip ./Lambda/Migrator/lambda_function.py ./Lambda/Selector/tools.py ./Lambda/variables.py
zip -j ./IaC/stablespot-paginator.zip ./Lambda/Paginator/lambda_function.py ./Lambda/Selector/tools.py ./Lambda/variables.py
zip -j ./IaC/stablespot-controller.zip ./Lambda/Controller/lambda_function.py ./Lambda/Selector/tools.py ./Lambda/variables.py
zip -j ./IaC/stablespot-registor.zip ./Lambda/Registor/lambda_function.py ./Lambda/Selector/tools.py ./Lambda/variables.py

python3.11 -m venv stablespotenv
source stablespotenv/bin/activate

pip install python-jose -t ./python
zip -r ./IaC/jose_layer.zip ./python

deactivate

terraform -chdir=./IaC/ init
terraform -chdir=./IaC/ apply -auto-approve

system_end_time=$(date +%s)

total_time=$((system_end_time - system_start_time))

echo Total time: $total_time sec
