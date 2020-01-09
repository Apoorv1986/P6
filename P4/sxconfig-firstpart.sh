cd /vagrant/P4/bf-sde-8.3.0/
source ./tools/set_sde.bash
# run tofino model with your P4 program (adjust name after -p flag)
./run_tofino_model.sh -p basictofino -f ../ports.json
