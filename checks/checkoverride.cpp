struct B
{
    virtual ~B() = default;
    virtual int foo() const = 0;
};

struct D : public B
{
    virtual int foo() const override { return 0; }
};

int main()
{
    B* b = new D;
    auto res = b->foo();
    delete b;
    return res;
}
