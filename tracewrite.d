#!/usr/sbin/dtrace -s

/* A DTrace script for tracing calls to both write and writev,
 * printing out the written bytes
 *
 * Because writev takes a vector, and DTrace doesn't support looping,
 * this script only prints the first 6 elements of the iovec
 * array
 */

struct iovec {
    char   *iov_base;  /* Base address. */
    size_t iov_len;    /* Length. */
};

struct msghdr {
    void        *msg_name;  /* [XSI] optional address */
    socklen_t   msg_namelen;    /* [XSI] size of address */
    struct      iovec *msg_iov; /* [XSI] scatter/gather array */
    int     msg_iovlen; /* [XSI] # elements in msg_iov */
    void        *msg_control;   /* [XSI] ancillary data, see below */
    socklen_t   msg_controllen; /* [XSI] ancillary data buffer len */
    int     msg_flags;  /* [XSI] flags on received message */
};

syscall::write:entry
/pid == $target && arg0 > 0 && arg2 > 0/
{
    self->write_data = arg1;
    self->write_len = arg2;
}

syscall::write:entry
/pid == $target && (arg0 == 0 || arg2 == 0)/
{
    self->write_len = 0;
}

syscall::write:return
/pid == $target && self->write_len > 1/
{
    printf("Write data (%d bytes): 0x%016x %.*S", self->write_len, (user_addr_t)self->write_data,
            self->write_len,
            stringof(copyin((user_addr_t)self->write_data, self->write_len)));
}

syscall::writev:entry
/pid == $target && arg2 > 0 && arg0 > 0/
{
    self->writev_data = arg1;
    self->writev_len = arg2;
}

syscall::writev:entry
/pid == $target && (arg2 == 0 || arg0 == 0)/
{
    self->writev_len = 0;
}

syscall::writev:return
/pid == $target && self->writev_len > 0/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 1/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[0].iov_len, (user_addr_t)vector[0].iov_base, 
            vector[0].iov_len,
            stringof(copyin((user_addr_t)vector[0].iov_base, vector[0].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 1/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 2/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[1].iov_len, (user_addr_t)vector[1].iov_base,
            vector[1].iov_len,
            stringof(copyin((user_addr_t)vector[1].iov_base, vector[1].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 2/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 3/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[2].iov_len, (user_addr_t)vector[2].iov_base, 
            vector[2].iov_len,
            stringof(copyin((user_addr_t)vector[2].iov_base, vector[2].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 3/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 4/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[3].iov_len, (user_addr_t)vector[3].iov_base, 
            vector[3].iov_len,
            stringof(copyin((user_addr_t)vector[3].iov_base, vector[3].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 4/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 5/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[4].iov_len, (user_addr_t)vector[4].iov_base, 
            vector[4].iov_len,
            stringof(copyin((user_addr_t)vector[4].iov_base, vector[4].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 5/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 6/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[5].iov_len, (user_addr_t)vector[5].iov_base, 
            vector[5].iov_len,
            stringof(copyin((user_addr_t)vector[5].iov_base, vector[5].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 6/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 7/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[6].iov_len, (user_addr_t)vector[6].iov_base, 
            vector[6].iov_len,
            stringof(copyin((user_addr_t)vector[6].iov_base, vector[6].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 7/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 8/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[7].iov_len, (user_addr_t)vector[7].iov_base, 
            vector[7].iov_len,
            stringof(copyin((user_addr_t)vector[7].iov_base, vector[7].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 8/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 9/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[8].iov_len, (user_addr_t)vector[8].iov_base, 
            vector[8].iov_len,
            stringof(copyin((user_addr_t)vector[8].iov_base, vector[8].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 9/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 10/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[9].iov_len, (user_addr_t)vector[9].iov_base, 
            vector[9].iov_len,
            stringof(copyin((user_addr_t)vector[9].iov_base, vector[9].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 10/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 11/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[10].iov_len, (user_addr_t)vector[10].iov_base, 
            vector[10].iov_len,
            stringof(copyin((user_addr_t)vector[10].iov_base, vector[10].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 11/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 12/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[11].iov_len, (user_addr_t)vector[11].iov_base, 
            vector[11].iov_len,
            stringof(copyin((user_addr_t)vector[11].iov_base, vector[11].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 12/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 13/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[12].iov_len, (user_addr_t)vector[12].iov_base, 
            vector[12].iov_len,
            stringof(copyin((user_addr_t)vector[12].iov_base, vector[12].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 13/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 14/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[13].iov_len, (user_addr_t)vector[13].iov_base, 
            vector[13].iov_len,
            stringof(copyin((user_addr_t)vector[13].iov_base, vector[13].iov_len)));
}

syscall::writev:return
/pid == $target && self->writev_len > 14/
{
    vector = (struct iovec *)copyin(self->writev_data, self->writev_len * sizeof(struct iovec));
    printf("Writev data 15/%d: (%d bytes): 0x%016x %.*S", self->writev_len, vector[14].iov_len, (user_addr_t)vector[14].iov_base, 
            vector[14].iov_len,
            stringof(copyin((user_addr_t)vector[14].iov_base, vector[14].iov_len)));
}
