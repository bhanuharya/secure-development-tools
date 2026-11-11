import { Controller, Get } from '@nestjs/common';

// No guard on the controller: the service-wide APP_GUARD is the only
// candidate, and this file cannot tell what it enforces.
@Controller('catalog')
export class CatalogController {
  @Get('items')
  items() {
    return [];
  }

  @Get('items/:id')
  item() {
    return {};
  }
}
