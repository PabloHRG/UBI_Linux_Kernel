// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Pablo Hernández Rodríguez (pablo.hernandezrd@gmail.com)
 */

 /*
  * UBI read counter sub-system.
  * This subsystem is in charge of managin the preventions against read
  * disturb.
  * This system manage the read counter updating of each PEB assuring that
  * it is initialized in the attaching process and stored in flash memory
  * during the detaching process.
  *
  * Further work will be to implement the refreshing process of a PEB,
  * every time the read counter overcome a certain threshold (let's
  * assume 60000).
  */

  #include <linux/crc32.h>
  #include <linux/err.h>
  #include <linux/slab.h>
  #include "ubi.h"

  /**
   * convertToTwoBytesWord - covert two words of 1 byte into a 2 bytes word
   * @byte: pointer to the two bytes
   *
   * This function returns the two bytes word
   */
  unsigned short convertToTwoBytesWord (unsigned char *byte)
  {
    return (byte[1] & 0xFF) | ((byte[0] & 0xFF) << 8);
  }

  /**
   * split_into_two_bytes - splir a two byte word into two bytes
   * @bigWord: word of two bytes
   *
   * This function returns a pointer of two words
   */
  unsigned char *split_into_two_bytes (unsigned short bigWord)
  {
    unsigned char * p;
    p = kmalloc(sizeof(unsigned char),GFP_KERNEL);
    *p = bigWord >> 8;
    *(p+1) = bigWord & 0xFF;
    return p;
  }

  /**
   * ubi_update_rc_sb_vid_hdr - update the superblock.
   * @ubi: UBI device description object
   * @pnum: pnum of the rc Superblock PEB
   *
   * This function returns zero in case of success, and a negative error code in
   * case of failure.
   */
  static int ubi_update_rc_sb_vid_hdr(struct ubi_device *ubi, int pnum){
    int err = 0;
    struct ubi_ec_hdr *ec_hdr;
    struct ubi_vid_io_buf *vidb;

    /* Initialize the ec_hdr object */
    ec_hdr = kzalloc(ubi->ec_hdr_alsize, GFP_KERNEL);
    if (!ec_hdr){
      kfree(ec_hdr);
      return -ENOMEM;
    }
    /* Initialize the vidb VID buffer */
    vidb = ubi_alloc_vid_buf(ubi, GFP_KERNEL);
    if (!vidb){
      return -ENOMEM;
    }
    /* Read the EC Header and store it in ec_hdr */
    err = ubi_io_read_ec_hdr(ubi, pnum, ec_hdr, 0);
    if (err != 0)
     return err;
    /* Read the VID Header and store it in vidb */
    err = ubi_io_read_vid_hdr(ubi, pnum, vidb, 0);
    if (err != 0)
     return err;
    /* Erase this PEB */
    err = do_sync_erase (ubi, pnum);
    if (err != 0)
     return err;
    /* Increment the erase counter */
    ec_hdr->ec += 1;
    /* Write the EC Header */
    err = ubi_io_write_ec_hdr(ubi, pnum, ec_hdr);
    if (err<0)
      return err;
    /* Write the VID Header */
    err = ubi_io_write_vid_hdr(ubi, pnum, vidb);
    if (err<0)
      return err;

    return err;
  }

  /**
   * ubi_init_first_rc - initialize the rc subsystem for free MTD
   * @ubi: UBI device description object
   * @ai: attaching information
   *
   * This function returns zero in case of success, and a negative error code in
   * case of failure.
   */
  static int ubi_init_first_rc (struct ubi_device *ubi,
                                struct ubi_attach_info *ai)
  {
    struct ubi_rc_entry *e;
    struct ubi_ainf_peb *aeb;
    struct ubi_rc_sb *rcsb;
    unsigned char *rcbuf, *tmp_rcbuf;
    int err, pnum, accum_size, len;

    accum_size = 0;

    /* Error initialization */
    err = -ENOMEM;

    /* Allocate memory for the rc lookup table */
    ubi->rc_lookuptbl = kcalloc(ubi->peb_count, sizeof(void *), GFP_KERNEL);
    if (!ubi->rc_lookuptbl)
      return err;

    /* Allocate memory for the super block */
    rcsb = kmalloc(sizeof(*rcsb), GFP_KERNEL);
    if (!rcsb)
      return err;

    /* Allocate  memory for the buffer for writing the rc data */
    rcbuf = kmalloc(ubi->rc_size, GFP_KERNEL);
    if (!rcbuf)
      return err;
    /* Since the MTD is free, put all the rc values to 0*/
    for (int i = 0; i< ubi->rc_size; i++)
    {
      rcbuf[i] = 0;
    }

    /* Seach for the first free available PEB
     * They will be not the 2 first LEBs, reserved for the volume table, because
     * the voulume table initialization is called before the rc initialization*/
    aeb = ubi_early_get_peb(ubi,ai);
    if (IS_ERR(aeb)) {
      err = PTR_ERR(aeb);
      return err;
    }
    /* Define the superblock pnum */
    ubi->rc_sb_pnum = cpu_to_be32(aeb->pnum);
    /* Superblock magic number*/
    rcsb->magic = cpu_to_be32(UBI_RC_SB_MAGIC);
    /* Calculate the number of PEBs necessaries for the rc */
    rcsb->used_blocks = cpu_to_be32(ubi_calc_rc_block_count(ubi));
    /* The first block_loc is the superblock */
    rcsb->block_loc[0] = cpu_to_be32(ubi->rc_sb_pnum);
    /* Define the data rc PEBs pnum */
    for (int i = 1; i < be32_to_cpu(rcsb->used_blocks); i++){
      aeb = ubi_early_get_peb(ubi,ai);
      if (IS_ERR(aeb)){
        err = PTR_ERR(aeb);
        return err;
      }
      rcsb->block_loc[i] = cpu_to_be32(aeb->pnum);
    }
    /* Erase and Write the headers of the rc superblock in flash*/
    ubi_update_rc_sb_vid_hdr (ubi,ubi->rc_sb_pnum);
    /* Write the superblock information in flash */
    err = ubi_io_write_data(ubi, rcsb, ubi->rc_sb_pnum , 0, sizeof(*rcsb));
    if (err<0)
      return err;

    /* Write the blocks used for rc data*/
    for (int i = 0; i < be32_to_cpu(rcsb->used_blocks); i++){
      pnum = be32_to_cpu(rcsb->block_loc[i]);
      /* Write the first block which is still the rc super block */
      if (i==0){
        /* Calculate the length if the rc needs more than one PEB */
        if (be32_to_cpu(rcsb->used_blocks) >1){
          len = ubi->leb_size - sizeof(*rcsb);
        }
        /* Calculate the length if all the data fits in the superblock PEB */
        else {
          len = ubi->rc_size - sizeof(*rcsb);
        }
        /* Allocate tmp_rcbuf */
        tmp_rcbuf = kmalloc(len, GFP_KERNEL);
        /* Store the data of rcbuf buffer in tmp_rcbuf with offset 0 */
        memcpy(tmp_rcbuf, rcbuf, len);
        /* Write it to the PEB*/
        err = ubi_io_write_data(ubi, tmp_rcbuf, pnum, sizeof(*rcsb), len);
        if(err<0)
          return err;
        /* Free the tmp_rcbuf*/
        kfree(tmp_rcbuf);
        /* Store in a variable the accumulate size used in the rcbuf */
        accum_size += len;
      }
      /* Write the last block of rc */
      else if (i == (be32_to_cpu(rcsb->used_blocks) - 1)){
        /* The length will be the rc_size minus the acc_size of the
         *previous blocks */
        len = ubi->rc_size - accum_size;
        /* Allocate tmp_rcbuf */
        tmp_rcbuf = kmalloc(len, GFP_KERNEL);
        /* Store the data of rcbuf buffer in tmp_rcbuf with offset accum_size */
        memcpy(tmp_rcbuf, rcbuf + accum_size, len);
        err = ubi_io_write_data(ubi, tmp_rcbuf, pnum, 0, len);
        if(err<0)
          return err;
        /* Free the tmp_rcbuf*/
        kfree(tmp_rcbuf);
      }
      /* Write the middle blocks of rc */
      else{
        /* if there is another block later, the length of the middle blocks
         * will be leb_size */
        len = ubi->leb_size;
        /* Allocate tmp_rcbuf */
        tmp_rcbuf = kmalloc(len, GFP_KERNEL);
        /* Store the data of rcbuf buffer in tmp_rcbuf with offset accum_size */
        memcpy(tmp_rcbuf, rcbuf + accum_size, len);
        err = ubi_io_write_data(ubi, tmp_rcbuf, pnum, 0, len);
        if(err<0)
          return err;
        /* Free the tmp_rcbuf*/
        kfree(tmp_rcbuf);
        /* Store in a variable the accumulate size used in the rcbuf */
        accum_size += len;
      }
    }

    /* Close the is_attach semaphore */
    ubi->is_attach = 0;
    /* Initialize the rc_lookuptbl */
    for (int i=0; i < ubi->peb_count; i++){
      /* Initialize the ubi_rc_entry */
      e = kmem_cache_alloc(ubi_rc_entry_slab, GFP_KERNEL);
      if (!e) {
        err = -ENOMEM;
        return err;
      }
      /* Assign the PEB number */
      e->pnum = i;
      /* The read counter will be the one counted during the attaching process */
      e->rc = ubi->rc_attachlkt[e->pnum]->rc;
      /* Store the entry in the lookuptbl */
      ubi->rc_lookuptbl[e->pnum] = e;
      kfree(tmp_rcbuf);
    }

    kfree(rcsb);
    kfree(rcbuf);
    return err;
 }

 /**
   * ubi_do_mtd_complet_refresh - refresh all the MTD for restart the rc
   * subsystem after a fatal error
   * @ubi: UBI device description object
   * @ai: attaching information
   *
   * This function returns zero in case of success, and a negative error code in
   * case of failure.
   * Maybe it is better to let the user decide if he wants to refresh all the
   * MTD or just initialice a new rc subsystem using the Kconfig
   */

 static int ubi_do_mtd_complet_refresh(struct ubi_device *ubi,
                                       struct ubi_attach_info *ai)
 {
   int err = 0;
   struct ubi_ec_hdr *ec_hdr;
   struct ubi_vid_io_buf *vidb;

   /* Initialize the ec_hdr object */
   ec_hdr = kzalloc(ubi->ec_hdr_alsize, GFP_KERNEL);
   if (!ec_hdr){
     kfree(ec_hdr);
     return -ENOMEM;
   }
   /* Initialize the vidb VID buffer */
   vidb = ubi_alloc_vid_buf(ubi, GFP_KERNEL);
   if (!vidb){
     return -ENOMEM;
   }
   /* Read, Erase and Write all the PEBs for restart all the read counters */
   for (int pnum = 0; pnum < ubi->peb_count; pnum++){
     /* Read the EC Header and store it in ec_hdr */
     err = ubi_io_read_ec_hdr(ubi, pnum, ec_hdr, 0);
     if (err != 0)
      return err;
     /* Read the VID Header and store it in vidb */
     err = ubi_io_read_vid_hdr(ubi, pnum, vidb, 0);
     if (err != 0)
      return err;
     /* Lock the use of UBI buf because the ubi->peb_buf is shared with other
      * functions */
     mutex_lock(&ubi->buf_mutex);
     /* Read the data area (LEB area) of the PEB and store it in ubi->peb_buf */
     err = ubi_io_read_data(ubi, ubi->peb_buf, pnum, 0, ubi->leb_size);
     if (err != 0)
      return err;
     /* Erase this PEB */
     err = do_sync_erase (ubi, pnum);
     if (err != 0)
      return err;
     /* Increment the erase counter */
     ec_hdr->ec += 1;
     /* Write the EC Header */
     err = ubi_io_write_ec_hdr(ubi, pnum, ec_hdr);
     if (err<0)
       return err;
     /* Write the VID Header */
     err = ubi_io_write_vid_hdr(ubi, pnum, vidb);
     if (err<0)
       return err;
     /* Write the data*/
     err = ubi_io_write_data(ubi, ubi->peb_buf, pnum, 0, ubi->leb_size);
     /* Unlock the ubi->peb_buf */
     mutex_lock(&ubi->buf_mutex);
   }
   /*Initialize the rc subsystem for a MTD previously without it
    *the read counters will be initialized*/
   err = ubi_init_first_rc(ubi,ai);
   return err;
 }


  /**
   * ubi_rc_init - initialize the rc subsystem using attaching information.
   * @ubi: UBI device description object
   * @ai: attaching information
   *
   * This function returns zero in case of success, and a negative error code in
   * case of failure.
   */
  int ubi_rc_init (struct ubi_device *ubi, struct ubi_attach_info *ai)
  {
    int err;
    struct ubi_rc_entry *e;
    struct ubi_rc_sb *rcsb;
    unsigned char *rcbuf, *tmp_rcbuf;
    int pnum;
    int len;
    int accum_size;

    /* Error initialization */
    err = -ENOMEM;

    /* Allocate memory for the rc lookup table */
    ubi->rc_lookuptbl = kcalloc(ubi->peb_count, sizeof(void *), GFP_KERNEL);
    if (!ubi->rc_lookuptbl)
      goto out_free;

    /* Allocate memory for the super block */
    rcsb = kmalloc(sizeof(*rcsb), GFP_KERNEL);
    if (!rcsb)
      return err;

    /* Allocate  memory for the buffer which read the rc data */
    rcbuf = kmalloc(ubi->rc_size, GFP_KERNEL);

    /* Initialize acc_size */
    accum_size = 0;

    /* if any rc super block has been found */
    if (ubi->rc_sb_pnum_counter == 0){
      /*
      * The MTD is firstly used or there has been a corruption in the rc
      * superblock
      * Because the PEBs has been analyzed with the late_analysis function
      * we assume that the MTD is not corrupted or have not UBI data so
      * we initialize the rc as if the MTD is totally free.
      */
      err = ubi_init_first_rc(ubi,ai);
    }
    else if (ubi->rc_sb_pnum_counter == 1){
      /*
       * There is only one rc superblock
       * Read the rc sb and manage errors
       */
      err = ubi_io_read_data(ubi, rcsb, ubi->rc_sb_pnum, 0, sizeof(*rcsb));

      /* Check if the magic number of the rc superblock is correct */
      if (be32_to_cpu(rcsb->magic) != UBI_RC_SB_MAGIC) {
        ubi_err(ubi, "bad rc super block magic: 0x%x, expected: 0x%x",
          be32_to_cpu(rcsb->magic), UBI_RC_SB_MAGIC);
        kfree(rcsb);
        /* if the magic number is incorrect refresh the MTD */
        err = ubi_do_mtd_complet_refresh(ubi,ai);
        if (err <0)
          return err;

        err = -1;
        goto out_free;
      }
      /* Check if the number of used blocks is correct */
      if (be32_to_cpu(rcsb->used_blocks) > UBI_RC_MAX_BLOCKS ||
          be32_to_cpu(rcsb->used_blocks) < 1) {
        ubi_err(ubi, "number of rc blocks is invalid: %i",
          be32_to_cpu(rcsb->used_blocks));

          kfree(rcsb);
          /* if the number of blocks is incorrect refresh the MTD */
          err = ubi_do_mtd_complet_refresh(ubi,ai);
          if (err <0)
            return err;

          err = -1;
          goto out_free;
      }
      /* Read the blocks used for rc and store them in rcbuf */
      for (int i = 0; i < be32_to_cpu(rcsb->used_blocks); i++){
        pnum = be32_to_cpu(rcsb->block_loc[i]);
        /* Read the first block which is still the rc super block */
        if (i==0){
          /* Calculate the length if the rc needs more than one PEB */
          if (be32_to_cpu(rcsb->used_blocks) > 1){
            len = ubi->leb_size - sizeof(*rcsb);
          }
          /* Calculate the length if all the data fits in the superblock PEB */
          else {
            len = ubi->rc_size - sizeof(*rcsb);
          }
          /* Store the data of this PEB in a temporary buffer */
          tmp_rcbuf = kmalloc(len, GFP_KERNEL);
          err = ubi_io_read_data(ubi, tmp_rcbuf, pnum, sizeof(*rcsb), len);
          if(err<0)
            goto out_free;
          /* Store the data of the temporary buffer in rcbuf witb offset 0 */
          memcpy(rcbuf, tmp_rcbuf, len);
          kfree(tmp_rcbuf);
          /* Store in a variable the accumulate size used in the rcbuf */
          accum_size += len;
        }
        /* Read the last block of rc */
        else if (i == (be32_to_cpu(rcsb->used_blocks) - 1)){
          /* The length will be the rc_size minus the acc_size of the
           *previous blocks */
          len = ubi->rc_size - accum_size;
          /* Store the data of this PEB in a temporary buffer */
          tmp_rcbuf = kmalloc(len, GFP_KERNEL);
          err = ubi_io_read_data(ubi, tmp_rcbuf, pnum, 0, len);
          if(err<0)
            goto out_free;
          /* Store the data of the temporary buffer in rcbuf
           * with offset accu_size */
          memcpy(rcbuf + accum_size, tmp_rcbuf, len);
          kfree(tmp_rcbuf);
        }
        /* Read the middle blocks of rc */
        else{
          /* if there is another block later, the length of the middle blocks
           * will be leb_size */
          len = ubi->leb_size;
          /* Store the data of this PEB in a temporary buffer */
          tmp_rcbuf = kmalloc(len, GFP_KERNEL);
          err = ubi_io_read_data(ubi, tmp_rcbuf, pnum, 0, len);
          if(err<0)
            goto out_free;
          /* Store the data of the temporary buffer in rcbuf
           * with offset accu_size */
          memcpy(rcbuf + accum_size, tmp_rcbuf, len);
          kfree(tmp_rcbuf);
          /* Store in a variable the accumulate size used in the rcbuf */
          accum_size += len;
        }
      }
      /* Close the is_attach semaphore */
      ubi->is_attach = 0;

      /* Initialize the rc_lookuptbl */
      for (int i=0; i < ubi->peb_count; i++){
        /* Initialize the ubi_rc_entry */
        e = kmem_cache_alloc(ubi_rc_entry_slab, GFP_KERNEL);
        if (!e) {
          err = -ENOMEM;
          goto out_free;
        }
        /* Assign the PEB number */
        e->pnum = i;
        /* Initialize the temporary buffer which will read two bytes
         * because the rc counter occupies two bytes */
        tmp_rcbuf = kmalloc(2*sizeof(unsigned char), GFP_KERNEL);
        /* Store subsequently 2 bytes of rcbuf in the temporary buffer */
        memcpy(tmp_rcbuf, rcbuf + i*2, 2);
        /* Convert the 2 bytes tmp_rcbuf pointer into a uint16_t and add the
         * rc counts during attaching process*/
        e->rc = convertToTwoBytesWord(tmp_rcbuf) +
                ubi->rc_attachlkt[e->pnum]->rc;
        /* Store the entry in the lookuptbl */
        ubi->rc_lookuptbl[e->pnum] = e;
        kfree(tmp_rcbuf);
      }
    }
    /* if ubi->rc_sb_pnum_counter is any other number, there has been an error
     * so the MTD is refreshed */
    else{
      err = ubi_do_mtd_complet_refresh(ubi,ai);
      if (err <0)
        return err;
    }

    /* free the buffers and return ok */
    kfree(rcsb);
    kfree(rcbuf);
    return 0;

    /* free the buffers and return ko */
    out_free:
      kfree (ubi->rc_lookuptbl);
      kfree(tmp_rcbuf);
      kfree(rcbuf);
      kfree(rcsb);
      return err;
  }

  /**
   * ubi_calc_rc_size - calculates in bytes the size necessary for storing the
   * read counter information for an UBI device.
   * @ubi: UBI device description object
   */
  size_t ubi_calc_rc_size(struct ubi_device *ubi)
  {
  	size_t size;
    /*
    * The size to store is the size of the superblock plus
    * the size of number of peb_counts * 2 (because every rc occupy 2 bytes)
    */
    size = sizeof(struct ubi_rc_sb) +
           (2 * (ubi->peb_count) * sizeof(unsigned char));


    /* Round the result to a multiple of the space of the leb */
    return roundup(size, ubi->leb_size);
  }

  /**
   * ubi_calc_rc_block_count - calculates the number of PEBs necessary
   * for storing the read counter information for an UBI device
   * @ubi: UBI device description object
   */
  int ubi_calc_rc_block_count(struct ubi_device *ubi)
  {
    return (ubi->rc_size/ubi->leb_size);
  }

  /**
   * ubi_check_rc_sb_data - check the rc_sb data
   * @ubi: UBI device description object
   * @pnum: pnum of the rc Superblock PEB
   *
   * This function returns 0 if the rc data is ok and a negative number if
   * it is not ok
   */
  int ubi_check_rc_sb_data(struct ubi_device *ubi, int pnum)
  {
    int err;
    struct ubi_rc_sb *rcsb;

    /* Error initialization */
    err = -ENOMEM;

    /* Allocate memory for the super block */
    rcsb = kmalloc(sizeof(*rcsb), GFP_KERNEL);
    if (!rcsb)
      return err;

    err = ubi_io_read_data(ubi, rcsb, ubi->rc_sb_pnum, 0, sizeof(*rcsb));
    if (err < 0)
      return err;

    /* Check if the magic number of the rc superblock is correct */
    if (be32_to_cpu(rcsb->magic) != UBI_RC_SB_MAGIC) {
      ubi_err(ubi, "bad rc super block magic: 0x%x, expected: 0x%x",
        be32_to_cpu(rcsb->magic), UBI_RC_SB_MAGIC);
      kfree(rcsb);

      err = -1;
    }
    /* Check if the number of used blocks is correct */
    if (be32_to_cpu(rcsb->used_blocks) > UBI_RC_MAX_BLOCKS ||
        be32_to_cpu(rcsb->used_blocks) < 1) {
      ubi_err(ubi, "number of rc blocks is invalid: %i",
        be32_to_cpu(rcsb->used_blocks));
        kfree(rcsb);

        err = -1;
    }

    return err;
  }

 /**
 * ubi_io_update_rc - Update the rc of a PEB defined by its pnum and
 * store it as an entry in the io_lookuptbl
 * @ubi: UBI device description object
 * @pnum: Number of the PEB
 *
 * This function returns zero in case of success, and a negative error code in
 * case of failure.
 */
 int ubi_update_rc(struct ubi_device *ubi, int pnum){
	int err;
	/* Error initialization */
	err = -ENOMEM;
	if (!ubi->rc_lookuptbl)
		return err;

	/* Increment the rc field for the rc_lookuptbl with index pnum */
	ubi->rc_lookuptbl[pnum]->rc += 1;
	return 0;
}

/**
 * ubi_reset_rc - Reset the rc of a PEB defined by its pnum and
 * store it as an entry in the rc_lookuptbl
 * @ubi: UBI device description object
 * @pnum: Number of the PEB
 *
 * This function returns zero in case of success, and a negative error code in
 * case of failure.
 */
int ubi_reset_rc(struct ubi_device *ubi, int pnum){
	int err;
	/* Error initialization */
	err = -ENOMEM;
	if (!ubi->rc_lookuptbl)
		return err;

	/* Reset the rc field for the io_lookuptbl with index pnum */
	ubi->rc_lookuptbl[pnum]->rc =0;

	return 0;
}


/**
 * ubi_rc_write_at_detach - write the current rc_lookuptbl in the PEBs of the
 * rc subsystem
 * @ubi: UBI device description object
 *
 * This function returns zero in case of success, and a negative error code in
 * case of failure.
 */
int ubi_rc_write_at_detach(struct ubi_device *ubi){
  struct ubi_rc_sb *rcsb;
  unsigned char *rcbuf, *tmp_rcbuf;
  int err, pnum, accum_size, bigWord, len;

  /* accum_size initialization */
  accum_size = 0;

  /* Error initialization */
  err = -ENOMEM;

  /* Allocate memory for the super block */
  rcsb = kmalloc(sizeof(*rcsb), GFP_KERNEL);
  if (!rcsb)
    return err;

  /* Allocate  memory for the buffer for writing the rc data */
  rcbuf = kmalloc(ubi->rc_size, GFP_KERNEL);
  if (!rcbuf)
    return err;

  /* Read the superblock information in flash */
  err = ubi_io_read_data(ubi, rcsb, ubi->rc_sb_pnum , 0, sizeof(*rcsb));
  if (err<0)
    return err;

  /* Store the rc_lookuptbl information in rcbuf */
  for (int i = 0; i< ubi->peb_count; i++)
  {
    /* Initialize the temporary buffer which will read two bytes
     * because the rc counter occupies two bytes */
    tmp_rcbuf = kmalloc(2*sizeof(unsigned char), GFP_KERNEL);
    /* Split the rc of the lookuptbl for storing it in the tmp_rcbuf
     * We add 3 * rcsb->used_blocks because in each write execution
     * after the rc counter should increse 3*/
    bigWord = ubi->rc_lookuptbl[i]->rc + 3 * rcsb->used_blocks;
    tmp_rcbuf = split_into_two_bytes((unsigned short)bigWord);
    /* Store subsequently tmp_rcbuf in the rcbuf */
    memcpy(rcbuf + 2*i, tmp_rcbuf, 2);
    /* free the tmp_rcbuf*/
    kfree(tmp_rcbuf);
  }
  /* Write the blocks used for rc data for the rc subsystem to be updated
   * for the next attach */
  for (int i = 0; i < be32_to_cpu(rcsb->used_blocks); i++){
    pnum = be32_to_cpu(rcsb->block_loc[i]);
    /* Write the first block which is still the rc super block */
    if (i==0){
      /* Calculate the length if the rc needs more than one PEB */
      if (be32_to_cpu(rcsb->used_blocks) >1){
        len = ubi->leb_size - sizeof(*rcsb);
      }
      /* Calculate the length if all the data fits in the superblock PEB */
      else {
        len = ubi->rc_size - sizeof(*rcsb);
      }
      /* Allocate tmp_rcbuf */
      tmp_rcbuf = kmalloc(len, GFP_KERNEL);
      /* Store the data of rcbuf buffer in tmp_rcbuf with offset 0 */
      memcpy(tmp_rcbuf, rcbuf, len);
      /* Write it to the PEB*/
      err = ubi_io_write_data(ubi, tmp_rcbuf, pnum, sizeof(*rcsb), len);
      if(err<0)
        return err;
      /* Free the tmp_rcbuf*/
      kfree(tmp_rcbuf);
      /* Store in a variable the accumulate size used in the rcbuf */
      accum_size += len;
    }
    /* Write the last block of rc */
    else if (i == (be32_to_cpu(rcsb->used_blocks) - 1)){
      /* The length will be the rc_size minus the acc_size of the
       *previous blocks */
      len = ubi->rc_size - accum_size;
      /* Allocate tmp_rcbuf */
      tmp_rcbuf = kmalloc(len, GFP_KERNEL);
      /* Store the data of rcbuf buffer in tmp_rcbuf with offset accum_size */
      memcpy(tmp_rcbuf, rcbuf + accum_size, len);
      err = ubi_io_write_data(ubi, tmp_rcbuf, pnum, 0, len);
      if(err<0)
        return err;
      /* Free the tmp_rcbuf*/
      kfree(tmp_rcbuf);
    }
    /* Write the middle blocks of rc */
    else{
      /* if there is another block later, the length of the middle blocks
       * will be leb_size */
      len = ubi->leb_size;
      /* Allocate tmp_rcbuf */
      tmp_rcbuf = kmalloc(len, GFP_KERNEL);
      /* Store the data of rcbuf buffer in tmp_rcbuf with offset accum_size */
      memcpy(tmp_rcbuf, rcbuf + accum_size, len);
      err = ubi_io_write_data(ubi, tmp_rcbuf, pnum, 0, len);
      if(err<0)
        return err;
      /* Free the tmp_rcbuf*/
      kfree(tmp_rcbuf);
      /* Store in a variable the accumulate size used in the rcbuf */
      accum_size += len;
    }
  }
  kfree(rcsb);
  kfree(rcbuf);
  return err;
}

/**
 * ubi_update_rc_sb_eba - update the superblock. This function is a helper to
 * the EBA system.
 * @ubi: UBI device description object
 * @pnum: pnum of the rc Superblock PEB
 * @from: PEB location to change in the superblock
 * @to: new PEB location
 *
 * This function returns zero in case of success, and a negative error code in
 * case of failure.
 */
int ubi_update_rc_sb_eba(struct ubi_device *ubi, int pnum, int from, int to){
  int err = 0;
  struct ubi_ec_hdr *ec_hdr;
  struct ubi_vid_io_buf *vidb;
  struct ubi_rc_sb *rcsb;

  /* Initialize the ec_hdr object */
  ec_hdr = kzalloc(ubi->ec_hdr_alsize, GFP_KERNEL);
  if (!ec_hdr){
    kfree(ec_hdr);
    return -ENOMEM;
  }
  /* Initialize the vidb VID buffer */
  vidb = ubi_alloc_vid_buf(ubi, GFP_KERNEL);
  if (!vidb){
    return -ENOMEM;
  }
  /* Allocate memory for the super block */
  rcsb = kmalloc(sizeof(*rcsb), GFP_KERNEL);
  if (!rcsb)
    return -ENOMEM;

  /* Read the EC Header and store it in ec_hdr */
  err = ubi_io_read_ec_hdr(ubi, pnum, ec_hdr, 0);
  if (err != 0)
   return err;
  /* Read the VID Header and store it in vidb */
  err = ubi_io_read_vid_hdr(ubi, pnum, vidb, 0);
  if (err != 0)
   return err;
  /* Lock the use of UBI buf because the ubi->peb_buf is shared with other
   * functions */
  mutex_lock(&ubi->buf_mutex);
  /* Read the data area (LEB area) of the PEB and store it in ubi->peb_buf */
  err = ubi_io_read_data(ubi, ubi->peb_buf, pnum, 0, ubi->leb_size);
  if (err != 0)
   return err;
  /* Erase this PEB */
  err = do_sync_erase (ubi, pnum);
  if (err != 0)
   return err;
  /* Increment the erase counter */
  ec_hdr->ec += 1;
  /* Write the EC Header */
  err = ubi_io_write_ec_hdr(ubi, pnum, ec_hdr);
  if (err<0)
    return err;
  /* Write the VID Header */
  err = ubi_io_write_vid_hdr(ubi, pnum, vidb);
  if (err<0)
    return err;
  /* Store the read superblock data in the rcsb object */
  memcpy(rcsb, ubi->peb_buf, sizeof(struct ubi_rc_sb));
  /* Update the rc superblock data */
  for (int i = 0; i < be32_to_cpu(rcsb->used_blocks); i++)
  {
    if (be32_to_cpu(rcsb->block_loc[i]) == from)
    {
      rcsb->block_loc[i] = cpu_to_be32(to);
      break;
    }
  }
  /* Update the ubi->peb_buf with the new superblock data */
  memcpy(ubi->peb_buf, rcsb, sizeof(struct ubi_rc_sb));
  /* Write the data */
  err = ubi_io_write_data(ubi, ubi->peb_buf, pnum, 0, ubi->leb_size);
  /* Unlock the ubi->peb_buf */
  mutex_lock(&ubi->buf_mutex);

  return err;
}


/**
 * ubi_update_vid_rc_sb - update the rc_sb of the VID Header. This function
 * is called inside ubi_io_write_vid_hdr
 * @ubi: UBI device description object
 * @pnum: pnum of the PEB
 * @vidb: VID buffer to store the rc_sb
 *
 * This function returns zero in case of success, and a negative error code in
 * case of failure.
 */
 int ubi_update_vid_rc_sb (struct ubi_device *ubi, int pnum,
                           struct ubi_vid_io_buf *vidb)
 {
   struct ubi_vid_hdr *vid_hdr = ubi_get_vid_hdr(vidb);
   if (pnum == ubi->rc_sb_pnum){
     vid_hdr->rc_sb = UBI_VID_HDR_MAGIC;
   }
   else{
     vid_hdr->rc_sb = 0;
   }
 }
