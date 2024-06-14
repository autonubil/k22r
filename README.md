

## Deployment


## kubernetes

```bash
kubectl apply -f deploy/daemonset.yaml 
```


### firewallcmd

```bash
cp deployment/k22r.xml /usr/lib/firewalld/services/opsanio.xml  
firewall-cmd --reload
firewall-cmd --add-service k22r --zone <what ever the node is on> --permanent
```
