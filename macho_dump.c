//MachDump by GeoSn0w (@FCE365)
//This tool dumps information from the 32-Bit and 64-Bit Mach-O binaries.
//Thanks for inspiration: https://lowlevelbits.org/parsing-mach-o-files/
//Happy dumping!
//~GeoSn0w, June 24 2018

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mach-o/swap.h>
#include <mach-o/loader.h>

int is_feedfacf(uint32_t magic);
void dump_ncmds_mach(FILE *object_file, int offset, int shouldSwap, uint32_t ncommands);
void dump_seg_mach(FILE *object_file);


int is_feedfacf(uint32_t magic){
  return magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
}

int swap_bytes(uint32_t magic){
  return magic == MH_CIGAM || magic == MH_CIGAM_64;
}

int main(int argc, char *argv[]){
  if (argc < 2){
    printf("\n[!] Not feeding me any Mach-O file? It's ok. I can find the exit myself.\n");
    printf("Usage: %s <mach-o 32/64-bit binary file path>\n\n", argv[0]);
    exit(EXIT_FAILURE);

  } else if (argc == 2){
    const char *file_path = argv[1];
    FILE *object_file = fopen(file_path, "rb");
    system("clear"); // Hell yee
    dump_seg_mach(object_file); //We out here
    fclose(object_file);
    return 0;

  } else if (argc > 2){
    printf("\nToo many commands!\nUsage: %s <mach-o 32/64-bit binary file path>\n\n", argv[0]);
    exit(EXIT_FAILURE);
  }
}

void *macho_loader(FILE *object_file, int offset, int size){
  void *buffer = calloc(1,size);
  fseek(object_file, offset,SEEK_SET);
  fread(buffer, size, 1, object_file);
  return buffer;
}

uint32_t mach_magic(FILE *object_file, int offset){
  uint32_t magic;
  fseek(object_file, offset, SEEK_SET);
  fread(&magic, sizeof(uint32_t), 1, object_file);
  printf("MachDump v1.0 by GeoSn0w (@FCE365)\n\nLocated Magic: 0x%x\nSwapped Magic: 0x%x\n", magic, NXSwapInt(magic));
  return magic;
}
void dump_header(FILE *object_file, int offset, int is_64, int shouldSwap){
  uint32_t ncmds;
  int lcmdoff = offset;
  if(is_64){
    int header_size = sizeof(struct mach_header_64);
    struct mach_header_64 *header = macho_loader(object_file, offset, header_size);
    if (shouldSwap){
      swap_mach_header_64(header, 0);
    }
    ncmds = header->ncmds;
    printf("[*] Found Mach-O 64-Bit Object File\n");
    printf("[*] Found CPU TYPE: 0x%.2x\n",header->cputype);
    printf("[*] Found CPU SUBTYPE: 0x%.2x\n",header->cpusubtype);
    printf("[*] Found FLAGS: 0x0%x\n",header->flags);
    printf("[*] Found Size: %d bytes\n",header->sizeofcmds);
    printf("===============================================\n");
    lcmdoff += header_size;
    free(header);
  } else {
    int header_size = sizeof(struct mach_header);
    struct mach_header *header = macho_loader(object_file, offset, header_size);
    if (shouldSwap){
      swap_mach_header(header, 0);
    }
    ncmds = header->ncmds;
      printf("[*] Found Mach-O 32-Bit Object File\n");
      printf("[*] Found CPU TYPE: %d\n",header->cputype);
      printf("[*] Found CPU SUBTYPE: %d\n",header->cpusubtype);
      printf("[*] Found FLAGS: 0x0%x\n",header->flags);
      printf("[*] Found Size: %d bytes\n",header->sizeofcmds);
      printf("===============================================\n");
    lcmdoff += header_size;
    free(header);
  }
  dump_ncmds_mach(object_file, lcmdoff, shouldSwap, ncmds);
}
void dump_ncmds_mach(FILE *object_file, int offset, int shouldSwap, uint32_t ncommands){
  int the_offset = offset;
  for (int i = 0; i < ncommands; i++){
    struct load_command *command = macho_loader(object_file, the_offset, sizeof(struct load_command));
    if (shouldSwap){
      swap_load_command(command, 0);
    }

    if (command->cmd == LC_SEGMENT_64){
      struct segment_command_64 *segment = macho_loader(object_file, the_offset, sizeof(struct segment_command_64));
      if (shouldSwap){
        swap_segment_command_64(segment, 0);
      }
      printf("[*] Found Segment: %s\n",segment->segname);
      printf("[*] Found Segment Memory Address (vmaddr): 0x%016llx\n",segment->vmaddr);
      printf("[*] Found Segment Memory Size (vmsize): 0x%016llx\n",segment->vmsize);
      printf("[*] Found %u structures in the segment\n",segment->nsects);
      printf("===============================================\n");
      free(segment);
    } else if (command->cmd == LC_SEGMENT){
      struct segment_command *segment = macho_loader(object_file, the_offset, sizeof(struct segment_command));
      if (shouldSwap){
        swap_segment_command(segment, 0);
      }
      printf("[*] Found Segment: %s\n",segment->segname);
      printf("[*] Found Segment Memory Address (vmaddr): 0x%016x\n",segment->vmaddr);
      printf("[*] Found Segment Memory Size (vmsize): 0x%016x\n",segment->vmsize);
      printf("[*] Found %u structures in the segment\n",segment->nsects);
      printf("===============================================\n");
      free(segment);
      //Try to retrieve main()'s address.
    } else if (command->cmd == LC_MAIN){
      struct entry_point_command *entry = macho_loader(object_file, the_offset, sizeof(struct entry_point_command));
      printf("[*] Found Main Entry Offset: 0x%llx\n",entry->entryoff);
      free(entry);
      //Symbol Table
    } else if (command->cmd == LC_SYMTAB){
      struct symtab_command *symtabl = macho_loader(object_file, the_offset, sizeof(struct symtab_command));
      printf("[*] Found Symbol Table at 0x%x and it has %d entries\n",symtabl->symoff, symtabl->nsyms);
      free(symtabl);
    }
    the_offset += command->cmdsize;
    free(command);
  }
}
void dump_seg_mach(FILE *object_file){
  uint32_t magic = mach_magic(object_file, 0);
  int is_64 = is_feedfacf(magic);
  int shouldSwap = swap_bytes(magic);
  dump_header(object_file, 0, is_64, shouldSwap);
}
