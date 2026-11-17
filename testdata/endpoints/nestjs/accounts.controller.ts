import { Controller, Delete, Param, Roles, UseGuards } from '@nestjs/common';
import { RolesGuard } from './roles.guard';

@Controller('accounts')
export class AccountsController {
  @UseGuards(RolesGuard)
  @Roles('admin', 'support')
  @Delete(':id')
  remove(@Param('id') id: string) {
    return { id };
  }
}
