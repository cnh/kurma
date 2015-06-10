# TODO

### Short Term

- [ ] cli: Implement sorting on container list
- [ ] cli: Implement using container names or short UUIDs for commands
- [ ] cli: Implement specifying the container name
- [ ] init: Add ability for arbitruary configuration to be passed to initial
  containers.
- [ ] stage1: Move local API to use a unix socket rather than localhost.
- [ ] stage1: Implement hook calls
- [ ] stage1: Implement appc isolators for capabilities
- [ ] stage1: Implement appc isolators for cgroups
- [ ] stage1: Add resource allocation
- [ ] stage1: Re-enable user namespace functionality
- [ ] Review Manager/Container lock handling
- [ ] Metadata API support
- [X] stage1: Support volumes
- [X] Look at a futex for protecting concurrent pivot_root calls.
- [X] cli: Add parameter for speciying a remote host to use
- [X] stage3: Updated User/Group username/uid handling to 0.6.0 spec
- [X] api: Implement remote API handling
- [X] Baseline validation of manifest before starting container
- [X] Support working directory
- [X] Implement configuring disks
- [X] Setup uid/gid look up in initd
- [X] Implement ability to enter a container
- [X] Address using switch\_root to re-enable pivot\_root for containers.
- [X] Instrument uid/gid handling for the stage3 exec
- [X] Implement PID 1 system bootstrapping
- [X] Implement "exited" handling for when the stage3 process exits
- [X] Implement appc isolators for namespaces
- [X] Implement remote image retrieval
- [X] Implement bootstrap containers

## Mid Term

- [ ] Multiple apps in a single pod
- [ ] Configurable configuration datasources
- [ ] Add whitelist support for where to retrieve an image from
- [ ] Add baseline enforcement of certain kernel namespaces, like mount, ipc,
  and pid.
- [ ] Have enter command look up user shell if none is given and use that for
  exec
- [X] Add support for image retrieval through an http proxy
- [X] Kernel module scoping for each environment

### Exploritory

- [ ] Investigate authentication with gRPC
- [X] Change management of containers to be separated by process, so the daemon
  doesn't need a direct handle on the container.
