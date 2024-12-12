#include <linux/module.h>       // Core header for kernel modules
#include <linux/kernel.h>       // Kernel log macros
#include <linux/netfilter_ipv4.h> // For Netfilter hooks
#include <linux/skbuff.h>       // For socket buffers
#include <linux/ip.h>           // IP header

// Function prototype for hook_func 
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// Hook function for packet filtering
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *IP_header;

    // Ensure the packet is valid
    if (!skb) //check if not null
        return NF_ACCEPT; //permits the packet to proceed

    // Extract the IP header
    IP_header = (struct iphdr *)skb_network_header(skb);
    if (!IP_header)
        return NF_ACCEPT;

    // Queue all packets for user-space processing
    printk(KERN_INFO "Queuing packet for user-space processing - Protocol: %u\n", IP_header->protocol);
    return NF_QUEUE;  // Send all packets to NFQUEUE
}

// Netfilter hook operations structure, tells where the hook function is and provides cetain details 
static struct nf_hook_ops firewall_ops = {
    .hook = hook_func,              // Hook function
    .pf = NFPROTO_IPV4,             // Protocol family (IPv4)
    .hooknum = NF_INET_LOCAL_IN,    // Hook point (incoming packets)
    .priority = NF_IP_PRI_FIRST,    // Priority of the hook
};

// Module initialization function
static int __init my_firewall_init(void) {
    printk(KERN_INFO "Initializing custom firewall module\n");
    return nf_register_net_hook(&init_net, &firewall_ops); //registers a netfilter hook in order to process the packet
}

//I got the help of github in this function
// Module cleanup function
static void __exit my_firewall_exit(void) {
    printk(KERN_INFO "Exiting custom firewall module\n");
    nf_unregister_net_hook(&init_net, &firewall_ops); //umregisters the netfilter hook
}

// Register module initialization and cleanup functions
module_init(my_firewall_init); //called when the module is loaded
module_exit(my_firewall_exit);//called when module is removed and cleans ups

MODULE_LICENSE("GPL"); //module compiles with open source licensing requirements
MODULE_AUTHOR("Enhanced by Assistant");
MODULE_DESCRIPTION("Custom Stateful Firewall Module - All Packets to NFQUEUE");