use regex::Regex;
use sha1::{Sha1, Digest};
use std::io::Error;

const EL: [&str; 18] = [
    "/usr/bin/kubectl:/usr/bin/bash:/usr/bin/su:/usr/bin/sudo:/usr/bin/sudo:/usr/bin/bash:/usr/sbin/sshd:/usr/sbin/sshd:/usr/sbin/sshd:/usr/lib/systemd/systemd:swapper/0 /user.slice sha256:401699ab870bb2d5053a517dc8c54a31f919e4440ea24121d14f4e4b46ba7fc5 /root/.kube/cache/discovery/10.1.199.232_6443/batch/v1/serverresources.json",
    "runc:/usr/bin/runc:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /run/containerd/io.containerd.runtime.v2.task/k8s.io/c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51/rootfs/run/xtables.lock",
    "runc:/usr/bin/runc:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /run/containerd/io.containerd.runtime.v2.task/k8s.io/c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51/rootfs/etc/hosts",
    "runc:/usr/bin/runc:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /run/containerd/io.containerd.runtime.v2.task/k8s.io/c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51/rootfs/etc/hostname",
    "runc:/usr/bin/runc:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /run/containerd/io.containerd.runtime.v2.task/k8s.io/c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51/rootfs/etc/resolv.conf",
    "runc:/usr/bin/runc:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:9003b1335e3ec8e426dbc715130569e08a708ee220c9c0d4ca6a0b730879607d /etc/passwd",
    "runc:/usr/bin/runc:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:190fcde0dc1f210f81c2977e4c9df5e97c5d712dd2300d573e36d24f57d77c67 /etc/group",
    "runc:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:df126187f448fd1cf49bd6f9052919ff0a25f959da76be330155d9ba773c52a6 /usr/local/bin/kube-proxy",
    "/usr/bin/containerd:/usr/lib/systemd/systemd:swapper/0 /system.slice/containerd.service sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /var/lib/containerd/io.containerd.grpc.v1.cri/containers/c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51/.tmp-status3105791586",
    "/usr/local/bin/kube-proxy:/usr/local/bin/kube-proxy:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:e712cde626a2b04d53a22ed7acb3cc3fe0d094259f1b311c0d74d7b6b325b212 /usr/sbin/iptables-wrapper",
    "/usr/local/bin/kube-proxy:/usr/local/bin/kube-proxy:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6 /bin/dash",
    "/bin/dash:/usr/local/bin/kube-proxy:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:363d859ffcdc0771c8ce1a15e971e0e14c11e07820d1a322c784edcea99890e3 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/bin/dash:/usr/local/bin/kube-proxy:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:2f4d5babd5bfe432a82d09619b2d757c6a83bfc4cac9899316ca5cd6d42890f3 /lib/x86_64-linux-gnu/libc.so.6",
    "/bin/dash:/bin/dash:/bin/dash:/bin/dash:/usr/local/bin/kube-proxy:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:64d15028cd703993760c4d0cbd9a0748682b650ce764a1d248261616d7760636 /usr/sbin/xtables-nft-multi",
    "/bin/dash:/bin/dash:/bin/dash:/usr/local/bin/kube-proxy:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:7480f7cb7110af0f45b6e04b50f8d1fb2c6392cf911cb3a28c516ef1b725823e /usr/bin/wc",
    "/bin/dash:/bin/dash:/bin/dash:/usr/local/bin/kube-proxy:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:9a9c5a0c3b5d1d78952252f7bcf4a992ab9ea1081c84861381380a835106b817 /bin/grep",
    "/usr/sbin/xtables-nft-multi:/bin/dash:/bin/dash:/bin/dash:/usr/local/bin/kube-proxy:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod09ccf5d0_d223_44da_8813_26c8ce8f15fb.slice/cri-containerd-c4e80505ae28bdf86fd65fba6a9c607b98894ed89be6308f21f543e3fbc37a51.scope sha256:f768c3d12a83096fb45fffbda1bfb24bc253f226a102cb79240a2bfa2e10568e /usr/lib/x86_64-linux-gnu/libxtables.so.12.7.0",
    "/usr/bin/kubectl:/usr/bin/bash:/usr/bin/su:/usr/bin/sudo:/usr/bin/sudo:/usr/bin/bash:/usr/sbin/sshd:/usr/sbin/sshd:/usr/sbin/sshd:/usr/lib/systemd/systemd:swapper/0 /user.slice sha256:fc3e3e68bd429d3c2b1a56c43b5ad339f1078cde7291a81ad9be0c0327c55c96 /root/.kube/cache/discovery/10.1.199.232_6443/storage.k8s.io/v1/serverresources.json",
];

pub struct Container {
    id: String,
    pod_id: String,
    event_log: String,
    vimr: Vec<u8>,
}

fn calc_measurement() -> Result<(), Error> {
    let vimr: [u8; 20] = [0; 20];
    let new_hash: [u8; 20] = [0; 20];
    let hash_con = [vimr, new_hash].concat();
    let mut hasher = Sha1::new();
    hasher.update(hash_con);
    println!("{:02x?}", hasher.finalize());
    Ok(())
}

pub fn get_containers() -> Result<Vec<Container>, Error> {
    let mut containers: Vec<Container> = vec![];
    let pod_id_re = Regex::new(r"kubepods-besteffort-pod|.slice")
        .unwrap();
    let container_id_re = Regex::new(r"cri-containerd-|.scope")
        .unwrap();

    for el in EL {
        if el.contains("cri-containerd") {
            let cgpath: Vec<&str> = el.split(" ").collect();
            if cgpath.len() != 4 {
                continue;
            }
            let cgroup: Vec<&str>  = cgpath[1].split('/').collect();
            let pod_id = pod_id_re.replace_all(cgroup[3], "");
            let container_id = container_id_re.replace_all(cgroup[4], "");
            println!("{}, {}", pod_id, container_id);
        }
    }
    let _ = calc_measurement();

    Ok(containers)
}
