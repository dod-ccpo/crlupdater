#!/usr/bin/env bash
#
# deploy/kubernetes/prod/update-deploy.sh: Updates the existing crlupdater deployment
#                                          with a new source image

set -o pipefail
set -o errexit
set -o nounset
# set -o xtrace

# Config
MAX_DEPLOY_WAIT='300'

if [[ $# -eq 0 ]]; then
  NAMESPACE=atat
else
  NAMESPACE=$1
fi

if [ "${IMAGE_NAME}x" = "x" ]
then
    IMAGE_NAME="${ATAT_DOCKER_REGISTRY_URL}/${PROD_IMAGE_NAME}:${GIT_SHA}"
fi

# Remove the K8S CA file when the script exits
function cleanup {
    printf "Cleaning up...\n"
    rm -vf "${HOME}/k8s_ca.crt"
    printf "Cleaning done."
}
trap cleanup EXIT

# Decode and save the K8S CA cert
echo "${K8S_CA_CRT}" | base64 -d - > "${HOME}/k8s_ca.crt"

# Setup the local kubectl client
kubectl config set-context deployer \
    --cluster=atat-cluster \
    --user=atat-deployer \
    --namespace=${NAMESPACE}

kubectl config set-cluster atat-cluster \
    --embed-certs=true \
    --server="${K8S_ENDPOINT}"  \
    --certificate-authority="${HOME}/k8s_ca.crt"

kubectl config set-credentials atat-deployer --token="$(echo ${K8S_USER_TOKEN} | base64 -d -)"

kubectl config use-context deployer
kubectl config current-context

echo .
echo "Deploying to cluster at: ${K8S_ENDPOINT}"
echo "With CA CRT: "
cat ${HOME}/k8s_ca.crt
echo .

# Update the crlupdater deployment
kubectl -n ${NAMESPACE} set image deployment.apps/crlupdater crlupdater="${IMAGE_NAME}"

# Wait for deployment to finish
if ! timeout -t "${MAX_DEPLOY_WAIT}" -s INT kubectl -n ${NAMESPACE} rollout status deployment/crlupdater
then
    # Deploy did not finish before max wait time; abort and rollback the deploy
    kubectl -n ${NAMESPACE} rollout undo deployment/crlupdater
    # Exit with a non-zero return code
    exit 2
fi
