class OrdersController {
    @PostMapping("/api/v1/feign/orders")
    void updateOrder(Order order) {
        orders.save(order);
    }
}
