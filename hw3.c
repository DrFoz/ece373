/*
 *Tyson Fosdick
 *ECE 373 Spring 2018
 *Assignment 3
 *30th, April 2018 
*/


#include <linux/module.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>

#define PCI_DEVICE_E100 0x8086
#define PE_LED_MASK 0xC
#define PE_REG_LEDS 0x0052

#define DEVCNT 5
#define DEVNAME "homework3"

static int majorNumber;

static struct mydev_dev {
        struct cdev cdev;
        //dev_t mydev_node;
        int syscall_val;
} mydev;

static dev_t mydev_node;

static struct pci_driver intel_eth_driver = {
	.name	= "pci_intel_eth",
	.id_table = intel_eth_pci_tbl,
	.probe	=intel_eth_probe,
	.remove	= intel_eth_remove

static int homework3_open(struct inode *inode, struct file *file){

        printk(KERN_INFO "Opened!\n");

        return 0;

}

static ssize_t homework3_read(struct file *file, char __user *buf, size_t len, loff_t *offset){

        int ret;

        if(*offset >= sizeof(int))
                return 0;

        if(!buf){
                ret = -EINVAL;
                goto out;
        }

        if(copy_to_user(buf, &mydev.syscall_val, sizeof(int))){
                ret = -EFAULT;
                goto out;
        }

        ret = sizeof(int);
        *offset += len;

        printk(KERN_INFO "User input %d\n", mydev.syscall_val);

out:
        return ret;
}

static ssize_t homework3_write(struct file *file, const char __user *buf, size_t len, loff_t *offset){
                int *kern_buf;
                int ret;

                if(!buf){
                        ret = -EINVAL;
                        goto out;
                }

                kern_buf = kmalloc(len, GFP_KERNEL);

                if(copy_from_user(kern_buf, buf, len)){
                        ret = -EFAULT;
                        goto out;
                }

                mydev.syscall_val = *kern_buf;
                printk(KERN_INFO "syscall now is %d\n", mydev.syscall_val);
                ret = len;

out:
                return ret;
}

static struct file_operations mydev_fops =
 {
                .owner = THIS_MODULE,
                .read = homework3_read,
                .open = homework3_open,
                .write = homework3_write,
};


static int __init homework3_init(void)
{
        int ret;
	majorNumber = register_chrdev(0, DEVNAME, &mydev_fops);

        printk(KERN_INFO "homework3 module loading...\n");
        mydev.syscall_val = 25;
        ret = alloc_chrdev_region(&mydev_node, 0, DEVCNT, DEVNAME);
        if(ret)
	{
                printk(KERN_ERR "alloc_chrdev_region() failed! ret=%d\n", ret);
                goto chrdev_err;
        }

        printk(KERN_INFO "Allocated %d devices at major %d\n", DEVCNT, MAJOR(mydev_node));

        cdev_init(&mydev.cdev, &mydev_fops);
        mydev.cdev.owner = THIS_MODULE;

        if(cdev_add(&mydev.cdev, mydev_node, DEVCNT))
	{
        printk(KERN_ERR "cdev_add() failed\n");
        goto cdev_err;
        }
                                                                                                                     
                 return ret;


cdev_err:
	unregister_chrdev_region(mydev_node, DEVCNT);

chrdev_err:
	return ret;
}

static void __exit homework3_exit(void){

        /* destory the cdev*/
        cdev_del(&mydev.cdev);

        /*clean up device*/
        unregister_chrdev_region(mydev_node, DEVCNT);

        printk(KERN_INFO "homework3 module unloaded!\n");
}

MODULE_AUTHOR("Tyson Fosdick");
MODULE_LICENSE("GPL");
MODULE_VERSION("1");
module_init(homework3_init);
module_exit(homework3_exit);

