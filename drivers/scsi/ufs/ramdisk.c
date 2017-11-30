#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/configfs.h>




static struct config_item *ramdisk_group_make_item(struct config_group *group, const char *name)
{
	return (struct config_item*)NULL;
}

static void ramdisk_group_drop_item(struct config_group *group, struct config_item *item)
{
}

static ssize_t ramdisk_group_features_show(struct config_item *item, char *page)
{
	return snprintf(page, PAGE_SIZE, "memory_backed,discard,bandwidth,cache,badblocks\n");
}

CONFIGFS_ATTR_RO(ramdisk_group_, features);


static struct configfs_attribute *ramdisk_group_attrs[] = {
	&ramdisk_group_attr_features,
	NULL,
};

static struct configfs_group_operations ramdisk_group_ops = {
	.make_item	= ramdisk_group_make_item,
	.drop_item	= ramdisk_group_drop_item,
};

static struct config_item_type ramdisk_group_type = {
	.ct_group_ops	= &ramdisk_group_ops,
	.ct_attrs	= ramdisk_group_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem ramdisk_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "ramdisk",
			.ci_type = &ramdisk_group_type,
		},
	},
};


static int __init ramdisk_init(void)
{
	int ret = 0;

	pr_err("RAMDISK: ramdisk init\n");
	config_group_init(&ramdisk_subsys.su_group);
	mutex_init(&ramdisk_subsys.su_mutex);
	ret = configfs_register_subsystem(&ramdisk_subsys);
	if (ret) {
		pr_err("RAMDISK: ramdisk_init: configfs_register_subsystem() failed\n");
		goto out;
	}

	pr_err("RAMDISK: ramdisk loaded\n");

out:
	return ret;
}

static void __exit ramdisk_exit(void)
{
	pr_err("RAMDISK: ramdisk exit\n");
	configfs_unregister_subsystem(&ramdisk_subsys);
}

module_init(ramdisk_init);
module_exit(ramdisk_exit);

MODULE_AUTHOR("Gnekiah Hsiung <gnekiah@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UFS host controller ramdisk driver");
