# UBI_Linux_Kernel
Modification of UBIFS to prevent read disturbance.
This extension of the UBIFS only works without fastmap mounting.
It needs further work to include the refreshing process of the PEBs 
when the read counter reach the threshold to be in danger of read disturbance
and to add the attaching with fastmap feauture.
