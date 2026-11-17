import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AccountsController } from './accounts.controller';
import { CatalogController } from './catalog.controller';
import { OrdersController } from './orders.controller';

@Module({
  controllers: [OrdersController, CatalogController, AccountsController],
  providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
})
export class AppModule {}
