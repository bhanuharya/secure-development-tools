// Annotated tests for the NestJS facts in rules/endpoint-facts/javascript.yaml.
import { Controller, Get, Post, Put, Patch, Delete, UseGuards, Roles, Public } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';

// ruleid: fact.nest.class_guard
@UseGuards(JwtAuthGuard)
@Controller('orders')
// ruleid: fact.nest.controller
export class OrdersController {
  // ruleid: fact.nest.route
  @Get()
  list() {
    return [];
  }

  // ruleid: fact.nest.method_guard
  @UseGuards(RolesGuard)
  // ruleid: fact.nest.method_roles
  @Roles('admin', 'support')
  // ruleid: fact.nest.route
  @Post('close')
  close() {
    return {};
  }

  // ruleid: fact.nest.method_public
  @Public()
  // ruleid: fact.nest.route
  @Get('health')
  health() {
    return {};
  }
}

// ruleid: fact.nest.class_guard
@UseGuards(JwtAuthGuard)
// ruleid: fact.nest.class_roles
@Roles('admin')
@Controller()
// ruleid: fact.nest.controller
class AccountsController {
  // ruleid: fact.nest.route
  @Put(':id')
  update() {
    return {};
  }

  // ruleid: fact.nest.route
  @Patch(':id/status')
  status() {
    return {};
  }

  // ruleid: fact.nest.route
  @Delete(':id')
  remove() {
    return {};
  }
}

// ruleid: fact.nest.class_public
@Public()
@Controller('health')
// ruleid: fact.nest.controller
class HealthController {}

// ruleid: fact.nest.app_guard
const guards = [{ provide: APP_GUARD, useClass: JwtAuthGuard }];

// ruleid: fact.nest.app_guard
app.useGlobalGuards(new RolesGuard());
