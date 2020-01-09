Vagrant.configure("2") do |config|
        config.vm.define "s1" do |s1|
                s1.vm.box = "p4-onos"
		s1.vm.network "private_network",ip: "10.10.1.100", netmask: "255.255.255.0",virtualbox__intnet: "controller"
                s1.vm.network "private_network",ip: "172.16.10.10", netmask: "255.255.255.0", mac: "000000000101", virtualbox__intnet: "source-s1"
                s1.vm.network "private_network",ip: "172.16.20.10", netmask: "255.255.255.0", mac: "000000000102", virtualbox__intnet: "s1-sink1"
                s1.vm.network "private_network",ip: "172.16.30.10", netmask: "255.255.255.0", mac: "000000000103", virtualbox__intnet: "s1-sink2"
                s1.vm.provider "virtualbox" do |virtualbox|
                        virtualbox.memory = "1024"
                        virtualbox.cpus = "1"
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc2", "allow-all"]
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc3", "allow-all"]
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc4", "allow-all"]
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc5", "allow-all"]
                        #virtualbox.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
                        virtualbox.customize [ "guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000 ]
                end

        end
        config.vm.define "sink1" do |sink1|
                sink1.vm.box = "loadgen"
                sink1.vm.network "private_network",ip: "172.16.20.100", netmask: "255.255.255.0", mac: "000000000410", virtualbox__intnet: "s1-sink1"
                sink1.vm.network "private_network",ip: "192.168.0.6", netmask: "255.255.255.252", mac: "000000000411", virtualbox__intnet: "sink1-agent"
                sink1.vm.provider "virtualbox" do |virtualbox|
                        virtualbox.memory = "1024"
                        virtualbox.cpus = "1"
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc2", "allow-all"]
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc3", "allow-all"]
                        virtualbox.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
                        virtualbox.customize [ "guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000 ]
                end
        end
        config.vm.define "sink2" do |sink2|
                sink2.vm.box = "loadgen"
                sink2.vm.network "private_network",ip: "172.16.30.100", netmask: "255.255.255.0", mac: "000000000412", virtualbox__intnet: "s1-sink2"
                sink2.vm.network "private_network",ip: "192.168.0.10", netmask: "255.255.255.252", mac: "000000000413", virtualbox__intnet: "sink2-agent"
                sink2.vm.provider "virtualbox" do |virtualbox|
                        virtualbox.memory = "1024"
                        virtualbox.cpus = "1"
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc2", "allow-all"]
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc3", "allow-all"]
                        virtualbox.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
                        virtualbox.customize [ "guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000 ]
                end
        end
        config.vm.define "source" do |source|
                source.vm.box = "loadgen"
                source.vm.network "private_network",ip: "172.16.10.100", netmask: "255.255.255.0", mac: "000000000110", virtualbox__intnet: "source-s1"
                source.vm.network "private_network",ip: "192.168.0.1", netmask: "255.255.255.252", mac: "000000000111", virtualbox__intnet: "source-agent"
                source.vm.provider "virtualbox" do |virtualbox|
                        virtualbox.memory = "512"
                        virtualbox.cpus = "1"
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc2", "allow-all"]
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc3", "allow-all"]
                        virtualbox.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
                        virtualbox.customize [ "guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000 ]
                end

        end
        config.vm.define "controller" do |controller|
                controller.vm.box = "p4-onos"
                controller.vm.network "private_network",ip: "10.10.1.10", netmask: "255.255.255.0",virtualbox__intnet: "controller"
                controller.vm.network "private_network",ip: "192.168.0.14", netmask: "255.255.255.252", virtualbox__intnet: "controller-agent"
                controller.vm.provider "virtualbox" do |virtualbox|
                        virtualbox.memory = "2048"
                        virtualbox.cpus = "2"
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc2", "allow-all"]
                        virtualbox.customize [ "guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000 ]
                end
        end
        config.vm.define "agent" do |agent|
                agent.vm.box = "ubuntu/bionic64"
                agent.vm.network "private_network",ip: "192.168.0.2", netmask: "255.255.255.252", mac: "000000000001", virtualbox__intnet: "source-agent"
                agent.vm.network "private_network",ip: "192.168.0.5", netmask: "255.255.255.252", mac: "000000000002", virtualbox__intnet: "sink1-agent"
                agent.vm.network "private_network",ip: "192.168.0.9", netmask: "255.255.255.252", mac: "000000000002", virtualbox__intnet: "sink2-agent"
                agent.vm.network "private_network",ip: "192.168.0.13", netmask: "255.255.255.252", mac: "000000000003", virtualbox__intnet: "controller-agent"
                agent.vm.provider "virtualbox" do |virtualbox|
                        virtualbox.memory = "2048"
                        virtualbox.cpus = "4"
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc2", "allow-all"]
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc3", "allow-all"]
                        virtualbox.customize ["modifyvm", :id,"--nicpromisc4", "allow-all"]
                        virtualbox.customize [ "modifyvm", :id, "--uartmode1", "disconnected" ]
                        virtualbox.customize [ "guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000 ]
                end
		agent.vm.provision "file", source: "~/.vagrant.d/boxes/loadgen/0/virtualbox/vagrant_private_key", destination: "vagrant_private_key"
        end
end
