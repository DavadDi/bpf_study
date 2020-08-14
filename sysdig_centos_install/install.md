# install sysdig on Linux

From: https://github.com/draios/sysdig/wiki/How-to-Install-Sysdig-for-Linux

**CentOS, RHEL, Fedora, Amazon Linux**

1) Trust the Draios GPG key, configure the yum repository
```
rpm --import https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public  
curl -s -o /etc/yum.repos.d/draios.repo https://s3.amazonaws.com/download.draios.com/stable/rpm/draios.repo
```

2) Install the EPEL repository

Note: The following command is required only if DKMS is not available in the distribution. You can verify if DKMS is available with `yum list dkms`

```
rpm -i https://mirror.us.leaseweb.net/epel/6/i386/epel-release-6-8.noarch.rpm
```

3) Install kernel headers

**Warning**: The following command might not work with any kernel. Make sure to customize the name of the package properly
```
yum -y install kernel-devel-$(uname -r)
```

4) Install sysdig
``` 
yum -y install sysdig
``` 

