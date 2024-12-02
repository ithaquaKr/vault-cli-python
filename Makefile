.PHONY: recreate remove pf

recreate:
	kubectl create namespace vault
	helm upgrade --install vault hashicorp/vault -n vault --values ./value-local.yaml

remove:
	kubectl delete namespace vault

pf:
	kubectl port-forward -n vault service/vault 8200:8200
