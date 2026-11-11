import { Controller, Get, Post, Public, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('orders')
@UseGuards(JwtAuthGuard)
export class OrdersController {
  @Get()
  list() {
    return [];
  }

  @Post()
  create() {
    return {};
  }

  // Explicitly open even though the controller is guarded.
  @Public()
  @Get('health')
  health() {
    return { status: 'ok' };
  }
}
