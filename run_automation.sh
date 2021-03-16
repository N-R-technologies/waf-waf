echo "Without WAF WAF"
python3 automation/automation.py False
echo
echo "With WAF WAF"
python3 automation/automation.py True
docker rm -f $(docker ps -a -q)
python3 automation/delete_resources